import type { ExtensionAPI, ExtensionContext, ToolCallEventResult } from "@earendil-works/pi-coding-agent";

const STATUS_KEY = "bash-guard-discussion";
const HOLD_REASON = "Paused by bash-guard for permission discussion. No permission was granted. " +
  "Answer the user's question or steering in text without further tool calls, then wait for their next message. " +
  "Do not retry the deferred operation yet; any later retry needs fresh permission checks.";

/** Native steering only reaches the model after tool preflight returns. Never wait for its answer here. */
export function registerPermissionDiscussion(pi: ExtensionAPI) {
  let turn = 0;
  let deferredTurn: number | undefined;
  let waitingForReply = false;

  const clear = (ctx: ExtensionContext) => {
    waitingForReply = false;
    ctx.ui.setStatus(STATUS_KEY, undefined);
  };
  const reset = (ctx: ExtensionContext) => {
    clear(ctx);
    deferredTurn = undefined;
    turn = 0;
  };

  pi.on("turn_start", () => { turn++; });
  pi.on("input", (event, ctx) => {
    if (event.source === "interactive" || event.source === "rpc") {
      if (waitingForReply) deferredTurn = turn;
      clear(ctx);
    }
    // A reply may arrive while the answer is still streaming. Hold that turn's calls too,
    // so normal checks resume on a fresh model turn rather than on its old in-flight plan.
  });
  pi.on("session_start", (_event, ctx) => reset(ctx));
  pi.on("session_shutdown", (_event, ctx) => reset(ctx));

  return {
    blockedCall(): ToolCallEventResult | undefined {
      if (deferredTurn !== turn && !waitingForReply) return undefined;
      return {
        block: true,
        reason: HOLD_REASON,
        // Let the original batch reach its queued question. Later tool-only retries must not loop.
        terminate: deferredTurn !== turn,
      };
    },

    defer(text: string, ctx: ExtensionContext, permissionDetails = ""): ToolCallEventResult {
      deferredTurn = turn;
      waitingForReply = true;
      ctx.ui.setStatus(STATUS_KEY, ctx.ui.theme.fg("warning", "bash-guard: discussing · reply to continue"));
      try {
        pi.sendUserMessage(text, { deliverAs: "steer" });
        ctx.ui.notify("Operation deferred, not approved or refused. Discuss in chat; your next message resumes permission checks.", "info");
      } catch {
        ctx.ui.notify("Could not queue the question. The operation remains deferred; send your message in chat.", "warning");
      }
      return {
        block: true,
        terminate: false,
        // Also retain the user's text in the result if native message dispatch fails asynchronously.
        reason: "Deferred by the user for discussion, not approved or refused. This tool call did not execute. " +
          HOLD_REASON + (permissionDetails ? `\n\nPermission context:\n${permissionDetails}` : "") +
          `\n\nUser question/steering:\n${text}`,
      };
    },
  };
}
