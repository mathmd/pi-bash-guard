import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { Decision } from "./types.ts";

const NAME = "bash-guard-yolo";
const USAGE = "Usage: /bash-guard-yolo [on|off|status] (no argument toggles)";

export interface YoloMode {
  /** Undefined leaves the normal permission flow in charge. Never weakens a deny. */
  automaticDecision(decision: Decision): "allow" | "deny" | undefined;
}

/** Explicit, in-memory approval automation. No policy, environment, or session-log state. */
export function registerYoloMode(pi: ExtensionAPI): YoloMode {
  let enabled = false;

  pi.registerFlag(NAME, {
    description: "Auto-allow bash-guard approval requests for the initial session; retain all hard denials",
    type: "boolean",
    default: false,
  });

  function updateStatus(ctx: ExtensionContext): void {
    if (!ctx.hasUI) return;
    ctx.ui.setStatus(NAME, enabled ? ctx.ui.theme.fg("warning", "⚠ bash-guard YOLO") : undefined);
  }

  function reportStatus(ctx: ExtensionContext): void {
    if (!ctx.hasUI) return;
    ctx.ui.notify(enabled
      ? "bash-guard YOLO ON: approval requests auto-allowed once; all hard denials remain. No sandbox is provided."
      : "bash-guard YOLO OFF: normal permission checks restored.", enabled ? "warning" : "info");
  }

  pi.registerCommand(NAME, {
    description: "Toggle session-local bash-guard YOLO approvals, or use on/off/status; hard denials remain",
    getArgumentCompletions: (prefix) => {
      const items = ["on", "off", "status"].filter((value) => value.startsWith(prefix))
        .map((value) => ({ value, label: value }));
      return items.length ? items : null;
    },
    handler: async (args, ctx) => {
      const action = args.trim();
      if (action === "") enabled = !enabled;
      else if (action === "on") enabled = true;
      else if (action === "off") enabled = false;
      else if (action !== "status") {
        if (ctx.hasUI) ctx.ui.notify(USAGE, "error");
        return;
      }
      updateStatus(ctx);
      reportStatus(ctx);
    },
  });

  pi.on("session_start", (event, ctx) => {
    // CLI flags survive Pi reloads/session switches; do not re-enable from a stale opt-in.
    enabled = event.reason === "startup" && pi.getFlag(NAME) === true;
    updateStatus(ctx);
    if (enabled) reportStatus(ctx);
  });

  pi.on("session_shutdown", (_event, ctx) => {
    enabled = false;
    updateStatus(ctx);
  });

  return {
    automaticDecision(decision) {
      if (!enabled) return undefined;
      return decision === "ask" ? "allow" : decision;
    },
  };
}
