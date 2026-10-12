import test from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import type { ExtensionAPI, ExtensionCommandContext, ExtensionContext, ToolCallEvent } from "@earendil-works/pi-coding-agent";
import { registerSubagentYolo, YOLO_BINDING } from "../subagent-yolo.ts";
import { registerYoloMode } from "../yolo-mode.ts";
import { createYoloAuthority, queryParentYolo, yoloRuntimeDirectory } from "../live-yolo.ts";
import { PolicyStore } from "../policy.ts";
import { GuardAnalyzer } from "../analyzer.ts";

type Handler = (event: Record<string, unknown>, ctx: ExtensionContext) => unknown;
type Command = Parameters<ExtensionAPI["registerCommand"]>[1];

function harness(file: string, parent?: string, flag = false) {
  const handlers = new Map<string, Handler[]>();
  const commands = new Map<string, Command>();
  const api = {
    on: (name: string, handler: Handler) => handlers.set(name, [...(handlers.get(name) ?? []), handler]),
    registerCommand: (name: string, command: Command) => commands.set(name, command),
    registerFlag: () => {}, getFlag: () => flag,
    registerTool: () => assert.fail("No model-callable mode toggle"),
    appendEntry: () => assert.fail("No mode stored in session history"),
  } as unknown as ExtensionAPI;
  const ctx = {
    hasUI: false, mode: "print",
    sessionManager: { getSessionFile: () => file, getHeader: () => ({ parentSession: parent }) },
    ui: new Proxy({}, { get: () => assert.fail("No headless UI") }),
  } as unknown as ExtensionCommandContext;
  const bridge = registerSubagentYolo(api);
  const mode = registerYoloMode(api, bridge);
  bridge.bindMode(mode.currentMode);
  const emit = async (name: string, fields: Record<string, unknown> = {}) => {
    for (const handler of handlers.get(name) ?? []) await handler({ type: name, ...fields }, ctx);
  };
  return {
    mode, bridge, ctx, emit,
    async start(bindings?: unknown, reason = "startup") {
      const previous = { child: process.env.PI_SUBAGENT_CHILD, bindings: process.env.PI_SUBAGENT_EXTENSION_BINDINGS };
      try {
        if (parent) process.env.PI_SUBAGENT_CHILD = "1";
        else delete process.env.PI_SUBAGENT_CHILD;
        if (bindings !== undefined) process.env.PI_SUBAGENT_EXTENSION_BINDINGS = typeof bindings === "string" ? bindings : JSON.stringify(bindings);
        else delete process.env.PI_SUBAGENT_EXTENSION_BINDINGS;
        await emit("session_start", { reason });
      } finally {
        if (previous.child === undefined) delete process.env.PI_SUBAGENT_CHILD; else process.env.PI_SUBAGENT_CHILD = previous.child;
        if (previous.bindings === undefined) delete process.env.PI_SUBAGENT_EXTENSION_BINDINGS; else process.env.PI_SUBAGENT_EXTENSION_BINDINGS = previous.bindings;
      }
    },
    command: (args: string) => commands.get("bash-guard-yolo")!.handler(args, ctx),
    prepare: (input: Record<string, unknown>) => bridge.prepare({ type: "tool_call", toolName: "subagent", toolCallId: "fixture", input } as ToolCallEvent, ctx),
    stop: () => emit("session_shutdown", { reason: "quit" }),
  };
}

async function fixture(body: (root: string, make: (name: string, parent?: string, flag?: boolean) => ReturnType<typeof harness>) => Promise<void>) {
  const root = mkdtempSync("/tmp/bash-guard-live-yolo-");
  const previous = process.env.TMPDIR;
  const sessions: ReturnType<typeof harness>[] = [];
  process.env.TMPDIR = root;
  try {
    await body(root, (name, parent, flag) => {
      const session = harness(join(root, name + ".jsonl"), parent && join(root, parent + ".jsonl"), flag);
      sessions.push(session);
      return session;
    });
  } finally {
    for (const session of sessions.reverse()) await session.stop();
    if (previous === undefined) delete process.env.TMPDIR; else process.env.TMPDIR = previous;
    assert.equal(spawnSync("gio", ["trash", "--", root]).status, 0);
  }
}

function call(options: Record<string, unknown> = {}) {
  return { agent: "worker", task: "fixture", async: true, options };
}
function bindings(input: ReturnType<typeof call>) { return input.options.extensionBindings; }

test("already-running children follow repeated live parent toggles; opt-out stays strict down the tree", async () => {
  await fixture(async (_root, make) => {
    const parent = make("parent"); await parent.start();
    const launch = call({ extensionBindings: { "another-extension/1": { unchanged: true } } });
    assert.equal(await parent.prepare(launch), undefined);
    assert.deepEqual((bindings(launch) as Record<string, unknown>)["another-extension/1"], { unchanged: true });
    const child = make("child", "parent"); await child.start(bindings(launch));
    const nestedLaunch = call(); assert.equal(await child.prepare(nestedLaunch), undefined);
    const nested = make("nested", "child"); await nested.start(bindings(nestedLaunch));
    const strictLaunch = call({ bashGuardInheritYolo: false });
    assert.equal(await parent.prepare(strictLaunch), undefined);
    assert.deepEqual(strictLaunch.options, {});
    const strict = make("strict", "parent", true); await strict.start(bindings(strictLaunch));
    const strictNestedLaunch = call(); await strict.prepare(strictNestedLaunch);
    const strictNested = make("strictNested", "strict", true); await strictNested.start(bindings(strictNestedLaunch));
    for (const action of ["off", "on", "off", "on", "off", "on"]) {
      await parent.command(action);
      assert.equal(await child.mode.currentMode(), action === "on");
      assert.equal(await nested.mode.currentMode(), action === "on");
      assert.equal(await strict.mode.currentMode(), false);
      assert.equal(await strictNested.mode.currentMode(), false);
    }
    const perStep = make("perStep", "parent", true);
    await perStep.start({ [YOLO_BINDING]: { inheritYolo: false } });
    assert.equal(await perStep.mode.currentMode(), false);
  });
});

test("concurrent parents, workflow defaults, caller metadata, and ambient foreground state cannot cross authority boundaries", async () => {
  await fixture(async (root, make) => {
    const one = make("one", undefined, true), two = make("two");
    await one.start(); await two.start();
    const launch = call(); await one.prepare(launch);
    const workflow: Record<string, unknown> = { workflow: true, options: { extensionBindings: { "another/1": 1 } } };
    assert.equal(await two.prepare(workflow), undefined);
    const oneChild = make("oneChild", "one"), twoChild = make("twoChild", "two");
    await oneChild.start(bindings(launch));
    await twoChild.start((workflow.options as Record<string, unknown>).extensionBindings);
    assert.equal(await oneChild.mode.currentMode(), true);
    assert.equal(await twoChild.mode.currentMode(), false);
    const wrong = make("wrong", "two", true); await wrong.start(bindings(launch));
    assert.equal(await wrong.mode.currentMode(), false);
    const foreground = make("foreground", "oneChild", true); await foreground.start(bindings(launch));
    assert.equal(await foreground.mode.currentMode(), false, "in-process nested child must not reuse enclosing runner metadata");
    const forged = call({ extensionBindings: { [YOLO_BINDING]: { inheritYolo: true, parentSessionFile: join(root, "one.jsonl") } } });
    assert.match((await two.prepare(forged))!, /parent metadata is supplied by the guard/);
    for (const input of [{ action: "resume", id: "fixture" }, { ...call(), async: false }, { ...call(), options: { resume: "fixture" } }]) {
      const before = structuredClone(input); await one.prepare(input); assert.deepEqual(input, before);
    }
    for (const input of [
      { action: "resume", options: { bashGuardInheritYolo: false } },
      { ...call(), resume: "fixture", options: { extensionBindings: { [YOLO_BINDING]: { inheritYolo: false } } } },
    ]) {
      const before = structuredClone(input);
      assert.match((await one.prepare(input))!, /retained children keep their original inheritance route/);
      assert.deepEqual(input, before, "resume opt-out must not be silently ignored or rewrite retained bindings");
    }
  });
});

test("shutdown, reload and malformed bindings fail closed without stale-mode or CLI fallback", async () => {
  await fixture(async (_root, make) => {
    const parent = make("parent", undefined, true); await parent.start();
    const launch = call(); await parent.prepare(launch);
    const child = make("child", "parent", true); await child.start(bindings(launch));
    assert.equal(await child.mode.currentMode(), true);
    for (const event of ["agent_settled", "session_compact", "session_tree"]) await parent.emit(event);
    assert.equal(await child.mode.currentMode(), true);
    await parent.stop();
    assert.equal(await child.mode.currentMode(), false);
    await parent.start(undefined, "reload");
    assert.equal(await child.mode.currentMode(), false);
    const fresh = call(); await parent.prepare(fresh);
    await parent.command("on");
    assert.equal(await child.mode.currentMode(), true, "a live same-session authority can be reattached, without replaying its mode");
    await child.start(bindings(launch), "reload");
    assert.equal(await child.mode.currentMode(), false);
    for (const value of ["not JSON", "x".repeat(16385), { [YOLO_BINDING]: { yolo: true } }, { [YOLO_BINDING]: { inheritYolo: "true" } }]) {
      const malformed = make("malformed", "parent", true); await malformed.start(value);
      assert.equal(await malformed.mode.currentMode(), false);
    }
    const standalone = make("standalone", undefined, true); await standalone.start(bindings(launch));
    assert.equal(await standalone.mode.currentMode(), true, "explicit standalone headless flag is independent of ambient child bindings");
  });
});

test("live mode grants neither ownership nor trust, and private channel records remain hard-denied", async () => {
  await fixture(async (root, make) => {
    const parent = make("parent", undefined, true); await parent.start();
    const launch = call(); await parent.prepare(launch);
    const child = make("child", "parent"); await child.start(bindings(launch));
    writeFileSync(join(root, ".env"), "fixture only");
    writeFileSync(join(root, "unowned.txt"), "fixture only");
    mkdirSync(join(root, ".git"));
    writeFileSync(join(root, ".git/config"), "");
    const store = new PolicyStore(join(root, "policy"), root, root);
    const analyzer = new GuardAnalyzer(store);
    const before = JSON.stringify(store.getPolicies());
    assert.equal(child.mode.automaticDecision(analyzer.analyzeCommand("unknown-fixture-command", root).decision, await child.mode.currentMode()), "allow");
    for (const command of ["cat .env", "shutdown now", "printf changed > .git/config", "rm unowned.txt"]) {
      const analysis = analyzer.analyzeCommand(command, root);
      assert.equal(analysis.decision, "deny", command);
      assert.equal(child.mode.automaticDecision(analysis.decision, await child.mode.currentMode()), "deny");
    }
    const runtime = yoloRuntimeDirectory();
    assert.equal(statSync(runtime).mode & 0o777, 0o700);
    for (const name of readdirSync(runtime).filter((name) => name.endsWith(".json"))) {
      const path = join(runtime, name);
      assert.equal(statSync(path).mode & 0o777, 0o600);
      const record = JSON.parse(readFileSync(path, "utf8"));
      assert.equal(Object.hasOwn(record, "enabled"), false);
      assert.equal(store.isSecret(path), true);
      for (const kind of ["read", "edit"] as const) assert.equal(analyzer.analyzePathAccess(path, kind, root, "fixture").decision, "deny");
    }
    assert.equal(JSON.stringify(store.getPolicies()), before);
  });
});

test("tampered or non-private rendezvous records cannot authorize or throw through the guard", async () => {
  await fixture(async (root) => {
    const file = join(root, "parent.jsonl");
    const authority = await createYoloAuthority(file, async () => true);
    const directory = yoloRuntimeDirectory();
    const recordFile = join(directory, readdirSync(directory).find((name) => name.endsWith(".json"))!);
    const original = readFileSync(recordFile, "utf8");
    const record = JSON.parse(original);
    try {
      assert.equal(await queryParentYolo(file), true);
      for (const invalid of [
        "null", "not JSON", " ".repeat(4097),
        JSON.stringify({ ...record, token: "0".repeat(64) }),
        JSON.stringify({ ...record, socket: "../elsewhere.sock" }),
        JSON.stringify({ ...record, socket: [record.socket] }),
        JSON.stringify({ ...record, token: [record.token] }),
        JSON.stringify({ ...record, sessionFile: join(root, "different.jsonl") }),
      ]) {
        writeFileSync(recordFile, invalid);
        assert.equal(await queryParentYolo(file), false);
      }
      writeFileSync(recordFile, original);
      chmodSync(recordFile, 0o644);
      assert.equal(await queryParentYolo(file), false);
      chmodSync(recordFile, 0o600);
      chmodSync(directory, 0o755);
      assert.equal(await queryParentYolo(file), false);
      chmodSync(directory, 0o700);
      assert.equal(await queryParentYolo(file), true);
    } finally {
      chmodSync(directory, 0o700);
      chmodSync(recordFile, 0o600);
      writeFileSync(recordFile, original);
      await authority.close();
    }
  });
});

test("unresponsive authorities, recursion and replacement cleanup are bounded and fail closed", async () => {
  await fixture(async (root) => {
    const file = join(root, "unresponsive.jsonl");
    const blocked = await createYoloAuthority(file, () => new Promise(() => {}));
    try { assert.equal(await queryParentYolo(file), false); } finally { await blocked.close(); }
    const first = await createYoloAuthority(file, async () => true);
    const second = await createYoloAuthority(file, async () => false);
    try {
      await first.close();
      assert.equal(await queryParentYolo(file), false);
      assert.equal(readdirSync(yoloRuntimeDirectory()).filter((name) => name.endsWith(".json")).length, 1);
      assert.equal(await queryParentYolo(file, 8), false);
    } finally { await second.close(); }
    assert.equal(await queryParentYolo(file), false);
  });
});
