import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import type { ExtensionAPI, ExtensionCommandContext, ExtensionContext, SessionStartEvent } from "@earendil-works/pi-coding-agent";
import { registerYoloMode } from "../yolo-mode.ts";
import { GuardAnalyzer } from "../analyzer.ts";
import { PolicyStore } from "../policy.ts";
import { strongest, type Decision } from "../types.ts";

const NAME = "bash-guard-yolo";
type Command = Parameters<ExtensionAPI["registerCommand"]>[1];
type Flag = Parameters<ExtensionAPI["registerFlag"]>[1];
type Handler = (event: { type: string; reason?: string }, ctx: ExtensionContext) => unknown;

function harness(flag?: boolean | string, hasUI = true) {
  const handlers = new Map<string, Handler[]>();
  const commands = new Map<string, Command>();
  const flags = new Map<string, Flag>();
  const statuses = new Map<string, string | undefined>();
  const notifications: Array<{ text: string; type?: string }> = [];
  const api = {
    on: (name: string, handler: Handler) => handlers.set(name, [...(handlers.get(name) ?? []), handler]),
    registerCommand: (name: string, command: Command) => commands.set(name, command),
    registerFlag: (name: string, definition: Flag) => flags.set(name, definition),
    getFlag: (name: string) => { assert.equal(name, NAME); return flag ?? flags.get(name)?.default; },
    appendEntry: () => assert.fail("YOLO must not persist state"),
    registerTool: () => assert.fail("YOLO must not expose a model-callable toggle"),
    sendUserMessage: () => assert.fail("YOLO must not trigger an agent turn"),
  } as unknown as ExtensionAPI;
  const ctx = {
    hasUI,
    mode: hasUI ? "tui" : "print",
    ui: hasUI ? {
      theme: { fg: (color: string, text: string) => `${color}:${text}` },
      setStatus: (key: string, text: string | undefined) => statuses.set(key, text),
      notify: (text: string, type?: string) => notifications.push({ text, type }),
      select: () => assert.fail("YOLO must not open a menu"),
      confirm: () => assert.fail("YOLO must not request confirmation"),
    } : new Proxy({}, { get: () => assert.fail("Headless YOLO must not use UI") }),
  } as unknown as ExtensionCommandContext;
  const yolo = registerYoloMode(api);
  const emit = async (type: string, reason?: string) => {
    for (const handler of handlers.get(type) ?? []) await handler({ type, reason }, ctx);
  };
  return {
    yolo, commands, flags, statuses, notifications, emit,
    start: (reason: SessionStartEvent["reason"] = "startup") => emit("session_start", reason),
    command: (args: string) => commands.get(NAME)!.handler(args, ctx),
  };
}

test("YOLO is opt-in, reports status, and never registers a model-callable toggle", async () => {
  const h = harness();
  assert.equal(h.flags.get(NAME)?.default, false);
  assert.equal(h.flags.get(NAME)?.type, "boolean");
  assert.equal(h.commands.size, 1);
  for (const decision of ["allow", "ask", "deny"] as Decision[]) {
    assert.equal(h.yolo.automaticDecision(decision), undefined);
  }
  await h.start();
  assert.equal(h.statuses.get(NAME), undefined);
  assert.equal(h.notifications.length, 0);
  await h.command("status");
  assert.equal(h.yolo.automaticDecision("ask"), undefined);
  assert.match(h.notifications.at(-1)!.text, /YOLO OFF/);
});

test("YOLO commands are explicit, idempotent, and visibly clear their status on off", async () => {
  const h = harness();
  await h.start();
  for (const args of ["on", " on ", "status", "on"]) {
    await h.command(args);
    assert.equal(h.yolo.automaticDecision("ask"), "allow");
    assert.equal(h.yolo.automaticDecision("allow"), "allow");
    assert.equal(h.yolo.automaticDecision("deny"), "deny");
    assert.match(h.statuses.get(NAME)!, /^warning:.*bash-guard YOLO/);
  }
  for (const args of ["on extra", "true", "unknown"]) {
    await h.command(args);
    assert.equal(h.yolo.automaticDecision("ask"), "allow");
    assert.match(h.notifications.at(-1)!.text, /^Usage:/);
    assert.equal(h.notifications.at(-1)!.type, "error");
  }
  for (const args of ["off", "off", "status"]) {
    await h.command(args);
    assert.equal(h.yolo.automaticDecision("ask"), undefined);
    assert.equal(h.statuses.get(NAME), undefined);
  }
  await h.command("invalid");
  assert.equal(h.yolo.automaticDecision("ask"), undefined);
  await h.command("");
  assert.equal(h.yolo.automaticDecision("ask"), "allow");
  await h.command("");
  assert.equal(h.yolo.automaticDecision("ask"), undefined);
  assert.equal(h.statuses.get(NAME), undefined);
  const complete = h.commands.get(NAME)!.getArgumentCompletions!;
  assert.deepEqual(await complete("o"), [{ value: "on", label: "on" }, { value: "off", label: "off" }]);
  assert.equal(await complete("no-match"), null);
});

test("YOLO accepts only a boolean CLI opt-in at initial startup, including headless runs", async () => {
  for (const flag of [undefined, false, "true", "false", true]) {
    const h = harness(flag, false);
    assert.equal(h.yolo.automaticDecision("ask"), undefined, "factory must wait for parsed flags at session_start");
    await h.start();
    assert.equal(h.yolo.automaticDecision("ask"), flag === true ? "allow" : undefined);
    await h.command("on");
    assert.equal(h.yolo.automaticDecision("ask"), "allow");
    assert.equal(h.yolo.automaticDecision("deny"), "deny");
    await h.command("off");
    assert.equal(h.yolo.automaticDecision("ask"), undefined);
  }
});

test("YOLO resets on session replacement and reload even when the CLI flag remains true", async () => {
  const reasons = ["reload", "new", "resume", "fork"] as const;
  for (const reason of reasons) {
    const h = harness(true);
    await h.start();
    assert.equal(h.yolo.automaticDecision("ask"), "allow");
    await h.emit("session_shutdown", reason);
    assert.equal(h.yolo.automaticDecision("ask"), undefined);
    assert.equal(h.statuses.get(NAME), undefined);
    // Pi normally recreates the factory, but the reset also works on an existing instance.
    await h.start(reason);
    assert.equal(h.yolo.automaticDecision("ask"), undefined);
    const rebound = harness(true);
    await rebound.start(reason);
    assert.equal(rebound.yolo.automaticDecision("ask"), undefined);
    assert.equal(rebound.statuses.get(NAME), undefined);
  }
  const h = harness();
  await h.command("on");
  await h.emit("session_shutdown", "quit");
  assert.equal(h.yolo.automaticDecision("ask"), undefined);
});

test("YOLO survives idle and compaction but is isolated between extension instances", async () => {
  const h = harness();
  const independent = harness();
  await h.start();
  await independent.start();
  await h.command("on");
  for (const type of ["turn_end", "agent_end", "agent_settled", "session_compact", "session_tree"]) {
    await h.emit(type);
    assert.equal(h.yolo.automaticDecision("ask"), "allow");
    assert.match(h.statuses.get(NAME)!, /bash-guard YOLO/);
    assert.equal(independent.yolo.automaticDecision("ask"), undefined);
  }
  await h.command("off");
  const restarted = harness();
  await restarted.start();
  assert.equal(restarted.yolo.automaticDecision("ask"), undefined);
});

test("YOLO consumes real analyses without granting ownership, changing policy, or weakening denials", async () => {
  const root = mkdtempSync("/tmp/bash-guard-yolo-");
  try {
    const workspace = join(root, "workspace");
    const extension = join(root, "extension");
    const home = join(root, "home");
    const system = join(root, "system-readonly");
    for (const path of [workspace, extension, home, system, join(workspace, ".git")]) mkdirSync(path);
    const target = join(workspace, "target.txt");
    const secret = join(workspace, ".env");
    const metadata = join(workspace, ".git", "config");
    const helper = join(workspace, "helper.sh");
    for (const path of [target, secret, metadata, join(system, "data")]) writeFileSync(path, "fixture\n");
    writeFileSync(helper, "#!/bin/sh\nprintf 'fixture'\n");
    const policy = new PolicyStore(extension, workspace, home, [system]);
    const analyzer = new GuardAnalyzer(policy);
    policy.save("local", {
      version: 3, ownership: { edit: [], execute: [], full: [] }, secrets: [], commands: { include: [], exclude: [] },
    });
    const before = readFileSync(policy.getLocalPath(), "utf8");
    const h = harness();
    await h.start();
    await h.command("on");
    const cases: Array<[string, Decision]> = [
      ["printf safe", "allow"],
      [`printf changed > '${target}'`, "ask"],
      [helper, "ask"],
      ["unknown-worker --inspect", "ask"],
      ["git add -- target.txt", "ask"],
      ['cat "$RUNTIME_PATH/data"', "ask"],
      ['rm "$RUNTIME_PATH/data"', "ask"],
      [`rm '${target}'`, "deny"],
      [`cat '${secret}'`, "deny"],
      [`printf changed > '${metadata}'`, "deny"],
      [`printf changed > '${system}/data'`, "deny"],
      ["shutdown now", "deny"],
      ["value=$(shutdown now)", "deny"],
      ["julia -e 'run(`shutdown now`)'", "deny"],
      [`unknown-worker --inspect; cat '${secret}'`, "deny"],
      [`cat '${secret}'; unknown-worker --inspect`, "deny"],
    ];
    for (const [command, expected] of cases) {
      const units = analyzer.analyzeCommandUnits(command, workspace);
      const decision = units.reduce<Decision>((result, unit) => strongest(result, unit.analysis.decision), "allow");
      assert.equal(decision, expected, command);
      assert.equal(h.yolo.automaticDecision(decision), expected === "deny" ? "deny" : "allow", command);
    }
    for (const kind of ["edit", "execute", "unknown"] as const) {
      const analysis = analyzer.analyzePathAccess(target, kind, workspace, "fixture-tool");
      assert.equal(analysis.decision, "ask");
      assert.equal(h.yolo.automaticDecision(analysis.decision), "allow");
    }
    const secretRead = analyzer.analyzePathAccess(secret, "read", workspace, "read");
    assert.equal(secretRead.decision, "deny");
    assert.equal(h.yolo.automaticDecision(secretRead.decision), "deny");
    await h.command("off");
    assert.equal(h.yolo.automaticDecision("ask"), undefined);
    assert.equal(analyzer.analyzeCommand(`printf changed > '${target}'`, workspace).decision, "ask");
    assert.equal(policy.ownership(target), "read");
    assert.equal(policy.ownership(helper), "read");
    assert.equal(readFileSync(policy.getLocalPath(), "utf8"), before);
    assert.equal(readFileSync(target, "utf8"), "fixture\n", "analyzed commands must never execute");
  } finally { execFileSync("gio", ["trash", "--", root]); }
});
