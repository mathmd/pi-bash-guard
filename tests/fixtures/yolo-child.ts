// Real SDK child in a separate process; only the provider responses are scripted.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { fauxAssistantMessage, fauxProvider, fauxToolCall } from "@earendil-works/pi-ai";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const config = JSON.parse(readFileSync(process.argv[2]!, "utf8"));
const subagents = dirname(fileURLToPath(import.meta.resolve("pi-subagents")));
const load = (relative: string) => import(pathToFileURL(join(subagents, relative)).href);
const { buildRunnerChildLaunch } = await load("src/runs/background/runner-child-launch.js");
const { createDefaultChildSessionFactory } = await load("src/runs/shared/child-session.js");
const factory = createDefaultChildSessionFactory({ loadPiCodingAgent: () => import("@earendil-works/pi-coding-agent") });
const faux = fauxProvider({ provider: "guard-probe", models: [{ id: "offline" }] });
const launch = buildRunnerChildLaunch({
  agent: "fixture", task: "fixture", tools: ["read", "write"],
  parentSessionId: "fixture-parent", parentSessionFile: config.parentFile,
  extensionBindings: config.bindings,
  inheritProjectContext: false, inheritGlobalContext: false, inheritSkills: false,
}, { cwd: config.workspace, id: "fixture-run", flatIndex: 0 }, {
  sessionEnabled: true, sessionDir: join(config.workspace, "sessions"), model: "guard-probe/offline",
});
launch.session.hooks.push({ name: "offline-provider", factory(pi: ExtensionAPI) { pi.registerProvider(faux.provider); } });
let session: Awaited<ReturnType<typeof factory.create>>;
try {
  session = await factory.create(launch.session);
  process.send!({ ready: true });
} catch (error) {
  process.send!({ error: String(error) });
  await factory.dispose();
  process.exit(1);
}
let queue = Promise.resolve();
process.on("message", (message: { id: number; tool?: "write" | "read"; args?: Record<string, string>; close?: boolean }) => {
  queue = queue.then(async () => {
    if (message.close) {
      await session.dispose(); await factory.dispose();
      process.send!({ id: message.id, closed: true }, () => process.exit(0));
      return;
    }
    faux.setResponses([
      fauxAssistantMessage(fauxToolCall(message.tool!, message.args!), { stopReason: "toolUse" }),
      fauxAssistantMessage("finished fixture"),
    ]);
    await session.prompt("Run the scripted fixture operation.");
    const result = [...session.messages].reverse().find((entry) => entry.role === "toolResult");
    process.send!({ id: message.id, result });
  }).catch((error) => { process.send!({ id: message.id, error: String(error) }); });
});
