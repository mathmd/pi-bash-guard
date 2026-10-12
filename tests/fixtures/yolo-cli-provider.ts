import { fauxAssistantMessage, fauxProvider, fauxToolCall } from "@earendil-works/pi-ai";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

export default function fixtureProvider(pi: ExtensionAPI): void {
  const faux = fauxProvider({ provider: "guard-probe", models: [{ id: "offline" }] });
  faux.setResponses([
    fauxAssistantMessage(fauxToolCall("write", { path: process.env.BASH_GUARD_TEST_TARGET!, content: "headless allowed" }), { stopReason: "toolUse" }),
    fauxAssistantMessage("finished fixture"),
  ]);
  pi.registerProvider(faux.provider);
}
