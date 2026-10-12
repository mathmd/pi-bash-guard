import { isAbsolute, resolve } from "node:path";
import type { ExtensionAPI, ExtensionContext, ToolCallEvent } from "@earendil-works/pi-coding-agent";
import { createYoloAuthority, queryParentYolo, type YoloAuthority } from "./live-yolo.ts";
import type { YoloModeHooks } from "./yolo-mode.ts";

export const YOLO_BINDING = "pi-bash-guard/1";
const BINDINGS_ENV = "PI_SUBAGENT_EXTENSION_BINDINGS";

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** Binding data identifies a route, never grants a permission. The live parent supplies the mode. */
function inheritedParent(ctx: ExtensionContext): string | false | undefined {
  const parent = ctx.sessionManager?.getHeader?.()?.parentSession;
  if (process.env.PI_SUBAGENT_CHILD !== "1" || !parent) return undefined;
  const raw = process.env[BINDINGS_ENV];
  if (!raw) return false;
  try {
    if (Buffer.byteLength(raw) > 16 * 1024) return false;
    const bindings: unknown = JSON.parse(raw);
    if (!record(bindings) || !record(bindings[YOLO_BINDING])) return false;
    const binding = bindings[YOLO_BINDING];
    if (Object.keys(binding).some((key) => key !== "inheritYolo" && key !== "parentSessionFile")) return false;
    if (binding.inheritYolo !== undefined && binding.inheritYolo !== true) return false;
    if (typeof binding.parentSessionFile !== "string" || !isAbsolute(parent) || !isAbsolute(binding.parentSessionFile)) return false;
    // A foreground descendant in the same runner can see its enclosing session's environment.
    // Only the SDK's actual parent backlink may select an authority; never use that ambient grant.
    return resolve(parent) === resolve(binding.parentSessionFile) ? resolve(parent) : false;
  } catch { return false; }
}

export interface SubagentYolo extends YoloModeHooks {
  bindMode(mode: (depth?: number) => Promise<boolean>): void;
  prepare(event: ToolCallEvent, ctx: ExtensionContext): Promise<string | undefined>;
}

export function registerSubagentYolo(pi: ExtensionAPI): SubagentYolo {
  let parent: string | false | undefined;
  let generation = 0;
  let active = false;
  let authority: Promise<YoloAuthority> | undefined;
  let authorityFile: string | undefined;
  let getMode: (depth?: number) => Promise<boolean> = async () => false;

  async function reset(): Promise<void> {
    active = false;
    generation++;
    parent = false;
    const previous = authority;
    authority = undefined;
    authorityFile = undefined;
    if (previous) await previous.then((value) => value.close(), () => {});
  }

  pi.on("session_start", async (event, ctx) => {
    await reset();
    parent = event.reason === "startup" ? inheritedParent(ctx) : undefined;
    active = true;
  });
  pi.on("session_shutdown", reset);
  pi.on("before_agent_start", (event) => ({
    systemPrompt: `${event.systemPrompt}\n\nbash-guard supports live YOLO inheritance for native background pi-subagents children that load this extension. Use async:true for supported launches; the parent user's on/off changes apply at each child permission decision. To opt a launch out, set options.bashGuardInheritYolo:false. For an individual scripted-workflow child, set extensionBindings:{"${YOLO_BINDING}":{"inheritYolo":false}}. Foreground/extension-isolated/external children are not covered; use options.bashGuardInheritYolo:false for external runners or workflows containing unsupported children. Retained children keep their original inheritance route; start a fresh child to change that route. Do not manufacture binding metadata or assume an unavailable parent authorizes execution.`,
  }));

  return {
    // Linked children have a local enable switch, but cannot exceed the live parent's permission.
    startup: () => parent === undefined ? undefined : parent !== false,
    async currentMode(depth = 0) {
      if (!active) return false;
      if (parent === undefined) return undefined;
      if (parent === false) return false;
      const current = generation;
      const enabled = await queryParentYolo(parent, depth);
      return current === generation && active && enabled;
    },
    bindMode(mode) { getMode = mode; },
    async prepare(event, ctx) {
      if (event.toolName !== "subagent" || (event.input.action !== undefined && event.input.action !== "resume") ||
          (!event.input.agent && !event.input.workflow && event.input.action !== "resume")) return;
      const options = event.input.options;
      if (options !== undefined && !record(options)) return "bash-guard: invalid subagent options";
      const existing = options?.extensionBindings;
      if (existing !== undefined && !record(existing)) return "bash-guard: invalid extensionBindings";
      const requested = existing?.[YOLO_BINDING];
      if (requested !== undefined && (!record(requested) || Object.keys(requested).length !== 1 || typeof requested.inheritYolo !== "boolean")) {
        return `bash-guard: ${YOLO_BINDING} accepts only inheritYolo:true or inheritYolo:false; parent metadata is supplied by the guard`;
      }
      // The official runner rejects replacement bindings on resume; never silently ignore an opt-out.
      if (event.input.action === "resume" || event.input.resume !== undefined || options?.resume !== undefined) {
        if (requested !== undefined || (options && Object.hasOwn(options, "bashGuardInheritYolo"))) {
          return "bash-guard: retained children keep their original inheritance route. Turn that parent off, or start a fresh child with options.bashGuardInheritYolo:false.";
        }
        return;
      }
      // This parent-side opt-out is removed before pi-subagents validates its own options.
      if (options && Object.hasOwn(options, "bashGuardInheritYolo")) {
        if (typeof options.bashGuardInheritYolo !== "boolean") return "bash-guard: bashGuardInheritYolo must be boolean";
        const disabled = options.bashGuardInheritYolo === false;
        delete options.bashGuardInheritYolo;
        if (disabled) {
          if (existing && Object.hasOwn(existing, YOLO_BINDING)) {
            const next = { ...existing }; delete next[YOLO_BINDING];
            if (Object.keys(next).length) options.extensionBindings = next;
            else delete options.extensionBindings;
          }
          return;
        }
      }
      if (event.input.async === false || options?.async === false) return;
      if (record(requested) && requested.inheritYolo === false) return;
      const sessionFile = ctx.sessionManager?.getSessionFile();
      if (!active || !sessionFile || !isAbsolute(sessionFile)) {
        return "bash-guard: live inheritance needs an active file-backed parent session. Set options.bashGuardInheritYolo:false to use ordinary child permissions.";
      }
      try {
        const current = generation;
        if (authorityFile !== sessionFile) {
          if (authority) await authority.then((value) => value.close(), () => {});
          authorityFile = sessionFile;
          authority = undefined;
        }
        authority ??= createYoloAuthority(sessionFile, async (depth) => active && current === generation && await getMode(depth));
        await authority;
        if (!active || current !== generation) return "bash-guard: parent session changed before delegation";
        event.input.options = {
          ...options,
          extensionBindings: { ...existing, [YOLO_BINDING]: { inheritYolo: true, parentSessionFile: resolve(sessionFile) } },
        };
      } catch {
        authority = undefined;
        return "bash-guard: live parent authority is unavailable. Retry after repairing local runtime storage, or explicitly opt this launch out of inheritance.";
      }
    },
  };
}
