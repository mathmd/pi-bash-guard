import test from "node:test";
import assert from "node:assert/strict";
import { copyFileSync, existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import type { ExtensionCommandContext, ToolCallEventResult } from "@earendil-works/pi-coding-agent";
import { loadFixtureExtension, piRequire, project } from "./pi-runtime.ts";
import { STEERING_CHOICE } from "../ui.ts";

type ToolCall = { type: "toolCall"; id: string; name: string; arguments: Record<string, unknown> };
type Content = ToolCall | { type: "text"; text: string };
type Message = { role: string; content: unknown; toolCallId?: string; isError?: boolean };
const toolCall = (id: string, name: string, args: Record<string, unknown>): ToolCall => ({ type: "toolCall", id, name, arguments: args });

for (const toolExecution of ["parallel", "sequential"]) {
  test(`permission steering reaches the next real agent turn without another approval (${toolExecution})`, { timeout: 15_000 }, async () => {
    const root = mkdtempSync("/tmp/bash-guard-steering-hooks-");
    const originalAgentDir = process.env.PI_CODING_AGENT_DIR;
    try {
      process.env.PI_CODING_AGENT_DIR = join(root, "agent");
      const extensionDir = join(root, "extension");
      const workspace = join(root, "workspace");
      mkdirSync(extensionDir); mkdirSync(workspace);
      for (const name of readdirSync(project)) {
        if (name.endsWith(".ts") || name === "package.json") copyFileSync(join(project, name), join(extensionDir, name));
      }
      symlinkSync(join(project, "node_modules"), join(extensionDir, "node_modules"), "dir");
      const policyDir = join(process.env.PI_CODING_AGENT_DIR, "bash-guard");
      mkdirSync(policyDir, { recursive: true });
      const policyPath = join(policyDir, "policy.json");
      const policyText = JSON.stringify({
        version: 3, ownership: { edit: [], execute: [], full: [] }, secrets: [],
        commands: { include: [], exclude: [] }, permissionTimeout: 0,
      });
      writeFileSync(policyPath, policyText);
      const target = join(workspace, "existing.txt");
      const created = join(workspace, "deferred-output.txt");
      writeFileSync(target, "unchanged");

      // Use the actual development Pi loader AND agent loop; only provider responses and tool bodies are mocked.
      const coreDir = dirname(piRequire.resolve("@earendil-works/pi-agent-core/package.json"));
      const { runAgentLoop } = await import(pathToFileURL(join(coreDir, "dist/agent-loop.js")).href);
      const { Type } = await import(pathToFileURL(piRequire.resolve("typebox")).href);
      const loaded = await loadFixtureExtension(join(extensionDir, "index.ts"), workspace);
      assert.deepEqual(loaded.errors, []);
      const extension = loaded.extensions[0]!;
      const statuses = new Map<string, string | undefined>();
      const menus: string[][] = [];
      const selections: string[] = [];
      const question = "Why is this operation necessary? Explain before I decide.";
      const ctx = {
        cwd: workspace, hasUI: true, mode: "rpc", isProjectTrusted: () => true,
        ui: {
          theme: { fg: (_color: string, text: string) => text },
          setStatus: (name: string, text: string | undefined) => statuses.set(name, text),
          notify: () => {},
          editor: async () => question,
          select: async (_title: string, options: string[]) => {
            menus.push([...options]);
            const choice = selections.shift();
            assert.ok(choice, "must not reopen permission while the question is waiting");
            assert.ok(options.includes(choice));
            return choice;
          },
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
      const queued: Message[] = [];
      const sends: Promise<void>[] = [];
      loaded.runtime.sendUserMessage = (content, options) => {
        assert.equal(options?.deliverAs, "steer");
        assert.equal(content, question);
        // Like Pi, delivery goes through extension input handling, then waits for the batch boundary.
        sends.push(emit("input", { text: content, source: "extension", streamingBehavior: "steer" }).then(() => {
          queued.push({ role: "user", content });
        }));
      };
      loaded.runtime.setActiveTools = () => assert.fail("must not replace the active tool set");
      loaded.runtime.appendEntry = () => assert.fail("must not persist approvals or discussion state");
      const executed: string[] = [];
      const outcomes = new Map<string, ToolCallEventResult | undefined>();
      const inputs = new Map<string, Record<string, unknown>>();
      const tools = [
        ["bash", Type.Object({ command: Type.String() })],
        ["read", Type.Object({ path: Type.String() })],
        ["write", Type.Object({ path: Type.String(), content: Type.String() })],
      ].map(([name, parameters]) => ({
        name, label: name, description: "Harmless fixture spy", parameters,
        execute: async (id: string) => {
          executed.push(id);
          return { content: [{ type: "text", text: "fixture result" }], details: {} };
        },
      }));
      const model = { id: "fixture", name: "fixture", provider: "fixture", api: "openai-completions" };
      let history: Message[] = [];
      async function run(script: Content[][], inspectRequest?: (messages: Message[], request: number) => void) {
        let requests = 0;
        const messages = await runAgentLoop([{ role: "user", content: "Fixture request", timestamp: Date.now() }],
          { systemPrompt: "Fixture only", messages: history, tools }, {
            model, toolExecution, convertToLlm: (messages: Message[]) => messages,
            getSteeringMessages: async () => { await Promise.all(sends); return queued.splice(0); },
            beforeToolCall: async ({ toolCall, args }: { toolCall: ToolCall; args: Record<string, unknown> }) => {
              const result = await emit("tool_call", { toolName: toolCall.name, toolCallId: toolCall.id, input: args });
              outcomes.set(toolCall.id, result); inputs.set(toolCall.id, args);
              return result;
            },
            afterToolCall: async ({ toolCall, args, isError }: { toolCall: ToolCall; args: Record<string, unknown>; isError: boolean }) => {
              await emit("tool_result", { toolName: toolCall.name, toolCallId: toolCall.id, input: args, isError });
            },
          }, async (event: { type: string } & Record<string, unknown>) => { await emit(event.type, event); }, undefined,
          (_model: unknown, context: { messages: Message[] }) => {
            inspectRequest?.(context.messages, requests);
            const content = script[requests++];
            assert.ok(content, "must not continue a tool-only discussion retry forever");
            const message = {
              role: "assistant", content, api: model.api, provider: model.provider, model: model.id,
              stopReason: content.some((item) => item.type === "toolCall") ? "toolUse" : "stop", timestamp: Date.now(),
              usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0,
                cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
            };
            return { async *[Symbol.asyncIterator]() { yield { type: "done", reason: message.stopReason, message }; }, result: async () => message };
          });
        history = [...history, ...messages];
        assert.equal(requests, script.length);
        return messages as Message[];
      }

      await emit("session_start", { reason: "startup" });
      const command = `unknown-worker --inspect; printf output > '${created}'`;
      selections.push(STEERING_CHOICE);
      const messages = await run([
        [toolCall("earlier-read", "read", { path: target }), toolCall("deferred", "bash", { command }),
          toolCall("sibling", "write", { path: target, content: "not executed" })],
        [{ type: "text", text: "Here is the explanation. I will wait for your decision." }],
      ], (messages, request) => {
        if (request !== 1) return;
        assert.ok(messages.some((message) => message.role === "user" && message.content === question));
        assert.equal(menus.length, 1, "the model must receive the question without another permission selection");
        assert.deepEqual(executed, ["earlier-read"], "previously admitted siblings may finish; deferred/later calls never execute");
      });
      assert.equal(messages.at(-1)!.role, "assistant");
      assert.equal(outcomes.get("deferred")?.block, true);
      assert.equal(outcomes.get("deferred")?.terminate, false);
      assert.match(outcomes.get("deferred")!.reason!, /Guard decision: ask/);
      assert.match(outcomes.get("deferred")!.reason!, /unknown-worker/);
      assert.equal(outcomes.get("sibling")?.block, true);
      assert.equal(inputs.get("deferred")!.command, command, "deferring does not rewrite the command");
      assert.equal(existsSync(created), false);
      assert.match(statuses.get("bash-guard-discussion")!, /reply to continue/);

      // Even a spurious successful result after external creation cannot grant the deferred call ownership.
      writeFileSync(created, "created elsewhere");
      await emit("tool_result", { toolName: "bash", toolCallId: "deferred", isError: false });
      await emit("input", { text: "Thanks, please reconsider.", source: "rpc" });
      await emit("turn_start");
      ctx.hasUI = false;
      const deletion = await emit("tool_call", { toolName: "bash", toolCallId: "unowned-delete", input: { command: `rm '${created}'` } });
      assert.match(deletion?.reason ?? "", /Permanent deletion without edit ownership/);
      ctx.hasUI = true;
      assert.equal(statuses.get("bash-guard-discussion"), undefined);
      selections.push("Allow once", "Allow once"); // Both unknown execution and the now-existing file require a fresh decision.
      await run([[toolCall("retry", "bash", { command })], [{ type: "text", text: "Finished." }]]);
      assert.equal(menus.length, 3);
      assert.deepEqual(executed, ["earlier-read", "retry"]);

      // A model that ignores the answer-only instruction cannot reopen menus or spin in a retry loop.
      selections.push(STEERING_CHOICE);
      await run([
        [toolCall("ask-again", "bash", { command: "unknown-worker --inspect" })],
        [toolCall("premature-retry", "bash", { command: "unknown-worker --inspect" }),
          toolCall("premature-write", "write", { path: target, content: "not executed" })],
      ]);
      assert.equal(menus.length, 4);
      assert.equal(outcomes.get("premature-retry")?.terminate, true);
      assert.equal(outcomes.get("premature-write")?.terminate, true);
      assert.deepEqual(executed, ["earlier-read", "retry"]);
      await extension.commands.get("bash-guard-yolo")!.handler("on", ctx);
      const heldUnderYolo = await emit("tool_call", { toolName: "bash", toolCallId: "yolo-retry", input: { command: "unknown-worker" } });
      assert.equal(heldUnderYolo?.block, true, "YOLO does not silently end an explicit discussion pause");
      await extension.commands.get("bash-guard-yolo")!.handler("off", ctx);

      // Questions about hard denials also hand off, but neither the question nor a chat reply grants permission.
      await emit("input", { source: "interactive", text: "Explain the next restriction." });
      const secret = join(workspace, ".env"); writeFileSync(secret, "fixture-secret");
      selections.push(STEERING_CHOICE);
      await run([[toolCall("denied-question", "bash", { command: `cat '${secret}'` })], [{ type: "text", text: "That is a secret read." }]]);
      assert.equal(menus.at(-1)!.includes("Allow once"), false);
      assert.match(outcomes.get("denied-question")!.reason!, /Guard decision: deny/);
      await emit("input", { source: "rpc", text: "Continue." });
      await emit("turn_start");
      ctx.hasUI = false;
      const stillDenied = await emit("tool_call", { toolName: "read", toolCallId: "still-secret", input: { path: secret } });
      assert.equal(stillDenied?.block, true);
      assert.match(stillDenied?.reason ?? "", /secret/i);
      assert.deepEqual(executed, ["earlier-read", "retry"]);
      assert.equal(readFileSync(target, "utf8"), "unchanged");
      assert.equal(readFileSync(policyPath, "utf8"), policyText);
      assert.equal(existsSync(join(workspace, ".pi", "bash-guard.json")), false);
    } finally {
      if (originalAgentDir === undefined) delete process.env.PI_CODING_AGENT_DIR;
      else process.env.PI_CODING_AGENT_DIR = originalAgentDir;
      execFileSync("gio", ["trash", "--", root]);
    }
  });
}
