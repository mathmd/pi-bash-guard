import test from "node:test";
import assert from "node:assert/strict";
import { copyFileSync, existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import type { ExtensionCommandContext, LoadExtensionsResult, ToolCallEventResult } from "@earendil-works/pi-coding-agent";

const project = dirname(dirname(fileURLToPath(import.meta.url)));

async function loadFixtureExtension(path: string, cwd: string): Promise<LoadExtensionsResult> {
  // Use the same installed Pi version as our TypeScript config, including its real jiti aliases.
  // Native Node cannot resolve Pi's injected runtime imports on its own.
  const config = JSON.parse(readFileSync(join(project, "tsconfig.json"), "utf8"));
  const piDist = dirname(config.compilerOptions.paths["@earendil-works/pi-coding-agent"][0]);
  const { loadExtensions } = await import(pathToFileURL(join(piDist, "core", "extensions", "loader.js")).href);
  return loadExtensions([path], cwd);
}

test("complete extension hooks automate YOLO asks, retain denies and creation tracking, and restore normal prompts", async () => {
  const root = mkdtempSync("/tmp/bash-guard-yolo-hooks-");
  try {
    const extensionDir = join(root, "extension");
    const workspace = join(root, "workspace");
    mkdirSync(extensionDir); mkdirSync(workspace);
    for (const name of readdirSync(project)) {
      if (name.endsWith(".ts") || name === "package.json") copyFileSync(join(project, name), join(extensionDir, name));
    }
    symlinkSync(join(project, "node_modules"), join(extensionDir, "node_modules"), "dir");
    const policyPath = join(extensionDir, "policy.json");
    const policyText = JSON.stringify({
      version: 3, ownership: { edit: [], execute: [], full: [] }, secrets: [],
      commands: { include: [], exclude: [] }, permissionTimeout: "1s",
    });
    writeFileSync(policyPath, policyText);
    const loaded = await loadFixtureExtension(join(extensionDir, "index.ts"), workspace);
    assert.deepEqual(loaded.errors, []);
    assert.equal(loaded.extensions.length, 1);
    const extension = loaded.extensions[0]!;
    assert.equal(extension.flags.get("bash-guard-yolo")!.default, false);
    assert.ok(extension.commands.has("bash-guard"));
    assert.ok(extension.commands.has("bash-guard-yolo"));
    const statuses = new Map<string, string | undefined>();
    let prompts = 0;
    const ctx = {
      cwd: workspace, hasUI: false, mode: "print", isProjectTrusted: () => true,
      ui: {
        theme: { fg: (_color: string, text: string) => text },
        setStatus: (name: string, value: string | undefined) => statuses.set(name, value),
        notify: () => {},
        select: async (_title: string, options: string[]) => {
          prompts++;
          assert.ok(options.includes("Allow once"));
          return "Allow once";
        },
        custom: () => assert.fail("YOLO must not open TUI components"),
        editor: () => assert.fail("YOLO must not open editors"),
      },
    } as unknown as ExtensionCommandContext;
    async function emit(type: string, fields: Record<string, unknown> = {}): Promise<ToolCallEventResult | undefined> {
      let result: ToolCallEventResult | undefined;
      for (const handler of extension.handlers.get(type) ?? []) {
        const value = await handler({ type, ...fields }, ctx);
        if (value) result = value as ToolCallEventResult;
        if (result?.block) break;
      }
      return result;
    }
    let serial = 0;
    const gate = (toolName: string, input: Record<string, unknown>, id = `call-${++serial}`) =>
      emit("tool_call", { toolName, input, toolCallId: id });
    const command = (args: string) => extension.commands.get("bash-guard-yolo")!.handler(args, ctx);

    await emit("session_start", { reason: "startup" });
    assert.equal((await gate("bash", { command: "unknown-worker --inspect" }))?.block, true);
    loaded.runtime.flagValues.set("bash-guard-yolo", true);
    await emit("session_start", { reason: "startup" });
    assert.equal(await gate("bash", { command: "unknown-worker --inspect" }), undefined);
    const target = join(workspace, "existing.txt");
    writeFileSync(target, "unchanged");
    assert.equal(await gate("write", { path: target, content: "changed" }), undefined);
    assert.equal(await gate("edit", { path: target, oldText: "unchanged", newText: "changed" }), undefined);
    assert.equal(await gate("fixture-tool", { outputPath: target }), undefined);
    assert.equal(await gate("bash", { command: `unknown-worker --inspect; printf changed > '${target}'` }), undefined);

    const secret = join(workspace, ".env");
    writeFileSync(secret, "fixture-secret");
    mkdirSync(join(workspace, ".git"));
    const metadata = join(workspace, ".git", "config");
    writeFileSync(metadata, "fixture-metadata");
    for (const input of [
      { command: `rm '${target}'` },
      { command: `unknown-worker --inspect; cat '${secret}'` },
      { command: `cat '${secret}'; unknown-worker --inspect` },
      { command: `printf changed > '${metadata}'` },
      { command: "value=$(shutdown now)" },
      { command: "julia -e 'run(`shutdown now`)'" },
    ]) {
      const before = JSON.stringify(input);
      const result = await gate("bash", input);
      assert.equal(result?.block, true);
      assert.match(result?.reason ?? "", /YOLO retains hard denials/);
      assert.equal(JSON.stringify(input), before, "must not rewrite deletion into trash");
    }
    assert.equal((await gate("read", { path: secret }))?.block, true);
    assert.equal(prompts, 0);

    // Simulate tool completion without executing any of the analyzed commands.
    const created = join(workspace, "created.txt");
    const createId = "successful-creation";
    assert.equal(await gate("bash", { command: `unknown-worker; printf created > '${created}'` }, createId), undefined);
    writeFileSync(created, "created");
    await emit("tool_result", { toolCallId: createId, toolName: "bash", isError: false });

    // A blocked compound call must not retain a pending creation and accidentally grant ownership.
    const blockedCreation = join(workspace, "blocked-output.txt");
    const blockedId = "blocked-creation";
    assert.equal((await gate("bash", { command: `printf blocked > '${blockedCreation}'; shutdown now` }, blockedId))?.block, true);
    writeFileSync(blockedCreation, "created elsewhere");
    await emit("tool_result", { toolCallId: blockedId, toolName: "bash", isError: false });
    await command("off");
    assert.equal(await gate("bash", { command: `rm '${created}'` }), undefined);
    assert.equal((await gate("bash", { command: `rm '${blockedCreation}'` }))?.block, true);
    assert.equal((await gate("bash", { command: "unknown-worker --inspect" }))?.block, true);
    assert.equal((await gate("write", { path: target, content: "changed" }))?.block, true);

    // RPC uses the normal menu path without requiring a real terminal or desktop notification.
    ctx.hasUI = true; ctx.mode = "rpc";
    assert.equal(await gate("bash", { command: "unknown-worker --inspect" }), undefined);
    assert.equal(prompts, 1);
    await command("on");
    ctx.mode = "tui";
    assert.match(statuses.get("bash-guard-yolo")!, /YOLO/);
    assert.equal(await gate("bash", { command: "unknown-worker --inspect" }), undefined);
    assert.equal((await gate("bash", { command: `rm '${target}'` }))?.block, true);
    assert.equal(prompts, 1, "YOLO opens neither approval nor refusal menus");
    await emit("session_shutdown", { reason: "reload" });
    assert.equal(statuses.get("bash-guard-yolo"), undefined);
    await emit("session_start", { reason: "reload" });
    assert.equal(statuses.get("bash-guard-yolo"), undefined, "stale startup flag cannot re-enable on reload");
    ctx.hasUI = false; ctx.mode = "print";
    assert.equal((await gate("bash", { command: "unknown-worker --inspect" }))?.block, true);
    assert.equal(readFileSync(policyPath, "utf8"), policyText);
    assert.equal(readFileSync(target, "utf8"), "unchanged");
    assert.equal(existsSync(join(workspace, ".pi", "bash-guard.json")), false);
  } finally {
    execFileSync("gio", ["trash", "--", root]);
  }
});
