import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { Decision } from "./types.ts";

const NAME = "bash-guard-yolo";
const USAGE = "Usage: /bash-guard-yolo [on|off|status] (no argument toggles)";

export interface YoloMode {
  /** Local switch; currentMode also checks any live parent restriction. */
  isEnabled(): boolean;
  currentMode(depth?: number): Promise<boolean>;
  /** Undefined leaves the normal permission flow in charge. Never weakens a deny. */
  automaticDecision(decision: Decision, enabled?: boolean): "allow" | "deny" | undefined;
}

export interface YoloModeHooks {
  startup?(ctx: ExtensionContext): boolean | undefined;
  currentMode?(depth?: number): Promise<boolean | undefined>;
}

/** In-memory approval automation, activated explicitly or by a scoped parent launch grant. */
export function registerYoloMode(pi: ExtensionAPI, hooks: YoloModeHooks = {}): YoloMode {
  let enabled = false;

  pi.registerFlag(NAME, {
    description: "Auto-allow bash-guard approval requests for the initial session; retain all hard denials",
    type: "boolean",
    default: false,
  });

  let generation = 0;
  async function currentMode(depth = 0): Promise<boolean> {
    if (!enabled) return false;
    const current = generation;
    const inherited = await hooks.currentMode?.(depth);
    return generation === current && enabled && inherited !== false;
  }

  function updateStatus(ctx: ExtensionContext, current = enabled): void {
    if (!ctx.hasUI) return;
    ctx.ui.setStatus(NAME, current ? ctx.ui.theme.fg("warning", "⚠ bash-guard YOLO") : undefined);
  }

  function reportStatus(ctx: ExtensionContext, current: boolean): void {
    if (!ctx.hasUI) return;
    ctx.ui.notify(current
      ? "bash-guard YOLO ON: approval requests auto-allowed once; all hard denials remain. No sandbox is provided."
      : "bash-guard YOLO OFF: normal permission checks restored.", current ? "warning" : "info");
  }

  function change(next: boolean, ctx: ExtensionContext): void {
    generation++;
    enabled = next;
    updateStatus(ctx);
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
      let next = enabled;
      if (action === "") next = !enabled;
      else if (action === "on") next = true;
      else if (action === "off") next = false;
      else if (action !== "status") {
        if (ctx.hasUI) ctx.ui.notify(USAGE, "error");
        return;
      }
      if (action !== "status") change(next, ctx);
      const current = await currentMode();
      updateStatus(ctx, current);
      reportStatus(ctx, current);
    },
  });

  pi.on("session_start", async (event, ctx) => {
    // Neither stale CLI flags nor a previous child's launch context may reactivate a replacement session.
    const next = event.reason === "startup" && (hooks.startup?.(ctx) ?? (pi.getFlag(NAME) === true));
    change(next, ctx);
    const current = await currentMode();
    updateStatus(ctx, current);
    if (current) reportStatus(ctx, current);
  });

  pi.on("session_shutdown", (_event, ctx) => change(false, ctx));

  return {
    isEnabled: () => enabled,
    currentMode,
    automaticDecision(decision, current = enabled) {
      if (!current) return undefined;
      return decision === "ask" ? "allow" : decision;
    },
  };
}
