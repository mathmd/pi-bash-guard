import test from "node:test";
import assert from "node:assert/strict";
import { copyFileSync, existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import type { ExtensionContext, ToolCallEventResult } from "@earendil-works/pi-coding-agent";
import { globalPolicyDirectory } from "../policy-location.ts";
import { emptyPolicy, PolicyStore } from "../policy.ts";
import { loadFixtureExtension, project } from "./pi-runtime.ts";

function fixture() {
  const root = mkdtempSync("/tmp/bash-guard-policy-location-");
  const agentDir = join(root, "agent");
  const directory = join(agentDir, "bash-guard");
  const destination = join(directory, "policy.json");
  const legacy = join(agentDir, "extensions", "bash-guard", "policy.json");
  const save = (path: string, text: string | Uint8Array) => { mkdirSync(dirname(path), { recursive: true }); writeFileSync(path, text); };
  return { root, agentDir, directory, destination, legacy, save, cleanup: () => execFileSync("gio", ["trash", "--", root]) };
}

test("new installations keep global policy outside packages without creating grants", () => {
  const f = fixture();
  try {
    f.save(join(f.agentDir, "git", "untrusted-package", "policy.json"), "invalid package policy");
    assert.equal(globalPolicyDirectory(f.agentDir), f.directory);
    assert.equal(existsSync(f.directory), false);
    const store = new PolicyStore(f.directory, f.root, f.root);
    assert.equal(store.globalPath, f.destination);
    assert.equal(store.isPolicyPath(f.destination), true);
    assert.equal(store.isTrustedCommand("fixture-worker", []), false);
  } finally { f.cleanup(); }
});

test("legacy user policy is copied exactly once, validated, private, and independent of its backup", () => {
  const f = fixture();
  try {
    const policy = { ...emptyPolicy(), commands: { include: [["fixture-worker", "--inspect"]], exclude: [] } };
    const text = JSON.stringify(policy, null, 4) + "\n";
    f.save(f.legacy, text);
    assert.equal(globalPolicyDirectory(f.agentDir), f.directory);
    assert.equal(readFileSync(f.destination, "utf8"), text);
    assert.equal(readFileSync(f.legacy, "utf8"), text);
    assert.equal(statSync(f.destination).mode & 0o777, 0o600);
    assert.notEqual(statSync(f.destination).ino, statSync(f.legacy).ino);
    assert.deepEqual(readdirSync(f.directory), ["policy.json"]);
    const store = new PolicyStore(f.directory, f.root, f.root);
    assert.equal(store.isTrustedCommand("fixture-worker", ["--inspect"]), true);
    f.save(f.legacy, "invalid old backup");
    globalPolicyDirectory(f.agentDir);
    assert.equal(readFileSync(f.destination, "utf8"), text);
  } finally { f.cleanup(); }
});

test("existing destination and symlink configuration are never overwritten by legacy grants", () => {
  const f = fixture();
  try {
    const realPolicy = join(f.root, "dotfiles", "guard.json");
    const text = JSON.stringify(emptyPolicy());
    f.save(realPolicy, text);
    f.save(f.legacy, "invalid old backup");
    mkdirSync(f.directory, { recursive: true });
    symlinkSync(realPolicy, f.destination);
    assert.equal(globalPolicyDirectory(f.agentDir), f.directory);
    assert.equal(readFileSync(realPolicy, "utf8"), text);
    // Even a dangling destination is user configuration, not permission to restore stale grants.
    execFileSync("gio", ["trash", "--", realPolicy]);
    assert.equal(globalPolicyDirectory(f.agentDir), f.directory);
    assert.equal(existsSync(realPolicy), false);
  } finally { f.cleanup(); }
});

test("invalid and older legacy policies are not silently migrated or discarded", () => {
  const f = fixture();
  try {
    for (const text of ["not JSON", '{"version":2}', '{"version":3}', JSON.stringify({ ...emptyPolicy(), commands: { include: ["invalid"], exclude: [] } })]) {
      f.save(f.legacy, text);
      assert.throws(() => globalPolicyDirectory(f.agentDir), /automatic schema migration is disabled/);
      assert.equal(existsSync(f.destination), false);
      assert.equal(readFileSync(f.legacy, "utf8"), text);
    }
  } finally { f.cleanup(); }
});

test("legacy preservation rejects malformed UTF-8 without changing either policy", () => {
  const f = fixture();
  try {
    const contents = Buffer.from(JSON.stringify({ ...emptyPolicy(), commands: { include: [["fixture-worker"]], exclude: [] } }));
    contents[contents.indexOf("fixture-worker")] = 0xff;
    f.save(f.legacy, contents);
    assert.throws(() => globalPolicyDirectory(f.agentDir), /UTF-8 version-3 JSON/);
    assert.equal(existsSync(f.destination), false);
    assert.deepEqual(readFileSync(f.legacy), contents);
  } finally { f.cleanup(); }
});

test("policy preservation rejects non-files and leaves state intact if the destination cannot be created", () => {
  const f = fixture();
  try {
    mkdirSync(f.legacy, { recursive: true });
    assert.throws(() => globalPolicyDirectory(f.agentDir), /must be a regular file/);
    execFileSync("gio", ["trash", "--", f.legacy]);
    const text = JSON.stringify(emptyPolicy());
    f.save(f.legacy, text);
    f.save(f.directory, "not a directory");
    assert.throws(() => globalPolicyDirectory(f.agentDir));
    assert.equal(readFileSync(f.directory, "utf8"), "not a directory");
    assert.equal(readFileSync(f.legacy, "utf8"), text);
  } finally { f.cleanup(); }
});

test("real hooks use agent-directory state across package locations and block failed preservation even under YOLO", async () => {
  const f = fixture();
  const previous = process.env.PI_CODING_AGENT_DIR;
  try {
    process.env.PI_CODING_AGENT_DIR = f.agentDir;
    const target = join(f.root, "existing.txt");
    writeFileSync(target, "unchanged");
    f.save(f.legacy, '{"version":2}');
    const notifications: string[] = [];
    const ctx = {
      cwd: f.root, hasUI: false, mode: "print", isProjectTrusted: () => true,
      ui: { setStatus: () => {}, notify: (text: string) => notifications.push(text), theme: { fg: (_color: string, text: string) => text } },
    } as unknown as ExtensionContext;
    async function load(name: string) {
      const extensionDir = join(f.root, name);
      mkdirSync(extensionDir);
      for (const file of readdirSync(project)) {
        if (file.endsWith(".ts") || file === "package.json") copyFileSync(join(project, file), join(extensionDir, file));
      }
      symlinkSync(join(project, "node_modules"), join(extensionDir, "node_modules"), "dir");
      // A checkout must not supply its own authority through an adjacent policy.
      writeFileSync(join(extensionDir, "policy.json"), JSON.stringify({ ...emptyPolicy(), ownership: { edit: [], execute: [], full: ["/**"] } }));
      const loaded = await loadFixtureExtension(join(extensionDir, "index.ts"), f.root);
      assert.deepEqual(loaded.errors, []);
      const emit = async (type: string, fields: Record<string, unknown> = {}): Promise<ToolCallEventResult | undefined> => {
        for (const handler of loaded.extensions[0]!.handlers.get(type) ?? []) {
          const result = await handler({ type, ...fields }, ctx) as ToolCallEventResult | undefined;
          if (result?.block) return result;
        }
      };
      return { loaded, emit };
    }
    const first = await load("first-checkout");
    first.loaded.runtime.flagValues.set("bash-guard-yolo", true);
    await first.emit("session_start", { reason: "startup" });
    assert.match(notifications.at(-1)!, /policy initialization failed/);
    const input = { command: "printf harmless" };
    const blocked = await first.emit("tool_call", { toolName: "bash", toolCallId: "failed-init", input });
    assert.equal(blocked?.block, true);
    assert.match(blocked!.reason!, /policy initialization failed/);
    assert.equal(input.command, "printf harmless");
    assert.equal(existsSync(f.destination), false);

    const text = JSON.stringify({ ...emptyPolicy(), secrets: [target] });
    f.save(f.legacy, text);
    await first.emit("session_start", { reason: "reload" });
    assert.equal(readFileSync(f.destination, "utf8"), text);
    for (const runtime of [first, await load("second-checkout")]) {
      await runtime.emit("session_start", { reason: "reload" });
      const denied = await runtime.emit("tool_call", { toolName: "read", toolCallId: "secret", input: { path: target } });
      assert.equal(denied?.block, true);
      assert.match(denied!.reason!, /Secret access is prohibited/);
      const unowned = join(f.root, "unowned.txt");
      writeFileSync(unowned, "unchanged");
      const write = await runtime.emit("tool_call", { toolName: "write", toolCallId: "write", input: { path: unowned, content: "changed" } });
      assert.equal(write?.block, true);
    }
    assert.equal(readFileSync(f.destination, "utf8"), text);
    assert.equal(readFileSync(f.legacy, "utf8"), text);
  } finally {
    if (previous === undefined) delete process.env.PI_CODING_AGENT_DIR; else process.env.PI_CODING_AGENT_DIR = previous;
    f.cleanup();
  }
});
