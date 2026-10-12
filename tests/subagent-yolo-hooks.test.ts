import assert from "node:assert/strict";
import { fork, spawnSync, type ChildProcess } from "node:child_process";
import { copyFileSync, existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { ExtensionCommandContext, ToolCallEventResult } from "@earendil-works/pi-coding-agent";
import { loadFixtureExtension, project, piDist } from "./pi-runtime.ts";

interface Reply { id?: number; ready?: boolean; error?: string; result?: { isError: boolean; content: unknown[] }; }
function childProcess(config: string, environment: NodeJS.ProcessEnv) {
  const process = fork(join(project, "tests/fixtures/yolo-child.ts"), [config], { env: environment, execArgv: [], stdio: ["ignore", "pipe", "pipe", "ipc"] });
  let diagnostics = "", id = 0;
  process.stdout!.on("data", (data) => { diagnostics += data; });
  process.stderr!.on("data", (data) => { diagnostics += data; });
  const wait = (request?: Record<string, unknown>): Promise<Reply> => new Promise((resolve, reject) => {
    const target = request ? ++id : undefined;
    const cleanup = () => { clearTimeout(timer); process.off("message", message); process.off("exit", exit); };
    const message = (reply: Reply) => {
      if (target === undefined ? !reply.ready && !reply.error : reply.id !== target) return;
      cleanup();
      if (reply.error) reject(new Error(reply.error + "\n" + diagnostics)); else resolve(reply);
    };
    const exit = (code: number | null) => { cleanup(); reject(new Error(`Fixture child exited ${code}: ${diagnostics}`)); };
    const timer = setTimeout(() => { cleanup(); reject(new Error(`Fixture child timed out: ${diagnostics}`)); }, 15_000);
    process.on("message", message); process.on("exit", exit);
    if (request) process.send({ ...request, id: target });
  });
  return { process, ready: wait(), request: wait };
}

test("official native runner children enforce live parent modes across processes without changing pi-subagents", { timeout: 60_000 }, async () => {
  const root = mkdtempSync(join(tmpdir(), "bash-guard-live-hooks-"));
  const agentDir = join(root, "agent"), extension = join(agentDir, "extensions/guard"), workspace = join(root, "work");
  mkdirSync(extension, { recursive: true }); mkdirSync(workspace);
  for (const name of readdirSync(project)) if (name.endsWith(".ts") || name === "package.json") copyFileSync(join(project, name), join(extension, name));
  symlinkSync(join(project, "node_modules"), join(extension, "node_modules"), "dir");
  mkdirSync(join(agentDir, "bash-guard"));
  const policyPath = join(agentDir, "bash-guard/policy.json");
  const policy = JSON.stringify({ version: 3, ownership: { edit: [], execute: [], full: [] }, secrets: [], commands: { include: [], exclude: [] }, permissionTimeout: 0 });
  writeFileSync(policyPath, policy);
  const originalAgentDir = process.env.PI_CODING_AGENT_DIR;
  process.env.PI_CODING_AGENT_DIR = agentDir;
  const originalTmpdir = process.env.TMPDIR;
  process.env.TMPDIR = root;
  const parentFile = join(root, "parent.jsonl");
  const context = {
    cwd: workspace, hasUI: false, mode: "print", isProjectTrusted: () => false,
    sessionManager: { getSessionFile: () => parentFile, getSessionId: () => "fixture-parent", getHeader: () => ({ id: "fixture-parent" }) },
    ui: { setStatus() {}, notify() {} },
  } as unknown as ExtensionCommandContext;
  const children: ChildProcess[] = [];
  let shutdown = async () => {};
  try {
    const loaded = await loadFixtureExtension(join(extension, "index.ts"), workspace);
    assert.deepEqual(loaded.errors, []);
    const guard = loaded.extensions[0]!;
    const emit = async (name: string, event: object) => {
      let result: ToolCallEventResult | undefined;
      for (const handler of guard.handlers.get(name) ?? []) {
        const value = await handler(event, context);
        if (value) result = value as ToolCallEventResult;
      }
      return result;
    };
    shutdown = async () => { await emit("session_shutdown", { type: "session_shutdown", reason: "quit" }); };
    await emit("session_start", { type: "session_start", reason: "startup" });
    const mode = (value: string) => guard.commands.get("bash-guard-yolo")!.handler(value, context);
    const start = async (name: string, inherit = true, header = parentFile) => {
      const input: Record<string, any> = { agent: "fixture", task: "Run fixture", options: {
        extensionBindings: { "fixture.other/1": { retained: true }, ...(inherit ? {} : { "pi-bash-guard/1": { inheritYolo: false } }) },
      } };
      assert.equal(await emit("tool_call", { type: "tool_call", toolCallId: name, toolName: "subagent", input }), undefined);
      assert.deepEqual(input.options.extensionBindings["fixture.other/1"], { retained: true });
      const config = join(root, `${name}.json`);
      writeFileSync(config, JSON.stringify({ workspace, parentFile: header, bindings: input.options.extensionBindings }));
      const environment: NodeJS.ProcessEnv = { ...process.env, PI_CODING_AGENT_DIR: agentDir, PI_SUBAGENT_CHILD: "1", PI_OFFLINE: "1" };
      delete environment.PI_PACKAGE_DIR;
      const child = childProcess(config, environment); children.push(child.process); await child.ready;
      return child;
    };
    const target = join(workspace, "unowned.txt");
    writeFileSync(target, "original"); writeFileSync(join(workspace, ".env"), "fixture only");
    const child = await start("inheriting"); // Starts with parent off, then survives repeated toggles.
    const attempt = async (allowed: boolean, text: string) => {
      const result = await child.request({ tool: "write", args: { path: target, content: text } });
      assert.equal(result.result?.isError, !allowed, JSON.stringify(result));
      if (allowed) assert.equal(readFileSync(target, "utf8"), text);
      else assert.notEqual(readFileSync(target, "utf8"), text);
    };
    await attempt(false, "off at spawn");
    await mode("on"); await attempt(true, "first on");
    await mode("off"); await attempt(false, "first off");
    await mode("on"); await attempt(true, "second on");
    const denied = await child.request({ tool: "read", args: { path: join(workspace, ".env") } });
    assert.equal(denied.result?.isError, true);
    assert.match(JSON.stringify(denied.result), /Secret access is prohibited/);
    const optedOut = await start("strict", false);
    const strict = await optedOut.request({ tool: "write", args: { path: target, content: "opt-out" } });
    assert.equal(strict.result?.isError, true);
    assert.equal(readFileSync(target, "utf8"), "second on");
    // A nested/foreground session must not adopt the enclosing runner's metadata.
    const mismatch = await start("different-header", true, join(root, "different-parent.jsonl"));
    const mismatched = await mismatch.request({ tool: "write", args: { path: target, content: "wrong parent" } });
    assert.equal(mismatched.result?.isError, true);
    await emit("session_shutdown", { type: "session_shutdown", reason: "quit" });
    await attempt(false, "parent gone");
    assert.equal(readFileSync(policyPath, "utf8"), policy);
    assert.equal(existsSync(join(workspace, ".pi/bash-guard.json")), false);
    await child.request({ close: true }); await optedOut.request({ close: true }); await mismatch.request({ close: true });
  } finally {
    await shutdown();
    await Promise.all(children.map((child) => new Promise<void>((done) => {
      if (child.exitCode !== null || child.signalCode !== null) return done();
      const force = setTimeout(() => child.kill("SIGKILL"), 1000);
      child.once("exit", () => { clearTimeout(force); done(); });
      child.kill();
    })));
    if (originalAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR; else process.env.PI_CODING_AGENT_DIR = originalAgentDir;
    if (originalTmpdir === undefined) delete process.env.TMPDIR; else process.env.TMPDIR = originalTmpdir;
    const cleanup = spawnSync("gio", ["trash", root], { encoding: "utf8" }); assert.equal(cleanup.status, 0, cleanup.stderr);
  }
});

test("standalone headless CLI still needs and honors its explicit YOLO flag", { timeout: 30_000 }, () => {
  const root = mkdtempSync(join(tmpdir(), "bash-guard-headless-yolo-"));
  try {
    const agentDir = join(root, "agent"), workspace = join(root, "work");
    mkdirSync(agentDir); mkdirSync(workspace);
    const target = join(workspace, "unowned.txt"); writeFileSync(target, "original");
    const environment: NodeJS.ProcessEnv = {
      ...process.env, PI_CODING_AGENT_DIR: agentDir, PI_OFFLINE: "1", TMPDIR: root,
      BASH_GUARD_TEST_TARGET: target,
    };
    delete environment.PI_PACKAGE_DIR; delete environment.PI_SUBAGENT_CHILD; delete environment.PI_SUBAGENT_EXTENSION_BINDINGS;
    const args = [join(piDist, "cli.js"), "--no-extensions", "--extension", join(project, "index.ts"),
      "--extension", join(project, "tests/fixtures/yolo-cli-provider.ts"),
      "--no-context-files", "--no-skills", "--no-themes", "--no-session", "--mode", "json", "--tools", "write", "--model", "guard-probe/offline"];
    const strict = spawnSync(process.execPath, [...args, "-p", "Run the scripted fixture operation"], {
      cwd: workspace, env: environment, encoding: "utf8", timeout: 10_000,
    });
    assert.equal(strict.status, 0, strict.stdout + strict.stderr);
    assert.equal(readFileSync(target, "utf8"), "original");
    assert.match(strict.stdout, /No interactive UI is available/);
    const yolo = spawnSync(process.execPath, [...args, "--bash-guard-yolo", "-p", "Run the scripted fixture operation"], {
      cwd: workspace, env: environment, encoding: "utf8", timeout: 10_000,
    });
    assert.equal(yolo.status, 0, yolo.stdout + yolo.stderr);
    assert.equal(readFileSync(target, "utf8"), "headless allowed", yolo.stdout + yolo.stderr);
    assert.equal(existsSync(join(agentDir, "bash-guard/policy.json")), false);
  } finally {
    const cleanup = spawnSync("gio", ["trash", root], { encoding: "utf8" }); assert.equal(cleanup.status, 0, cleanup.stderr);
  }
});
