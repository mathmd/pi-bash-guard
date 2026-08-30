import type { ExtensionCommandContext, ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { Analysis } from "./types.ts";
import type { PolicyScope, PolicyStore } from "./policy.ts";
import { openPolicyInEditor } from "./external-editor.ts";

export type PromptDecision = { action: "allow" | "refuse" | "trash"; context?: string };
class MenuCancelled extends Error {}

function summary(analysis: Analysis, subject: string): string {
  const reasons = analysis.reasons.map((reason) => `• ${reason}`).join("\n");
  return `${subject}\n\n${reasons}`;
}

export interface DetailViewport {
  lines: string[];
  offset: number;
  pageSize: number;
  total: number;
}

export function detailViewport(text: string, width: number, terminalRows: number, optionCount: number, requestedOffset = 0): DetailViewport {
  const availableWidth = Math.max(20, width - 2);
  const wrapped: string[] = [];
  for (const source of text.split("\n")) {
    if (!source) {
      wrapped.push("");
      continue;
    }
    for (let start = 0; start < source.length; start += availableWidth) wrapped.push(source.slice(start, start + availableWidth));
  }
  const availableRows = Math.max(3, terminalRows - optionCount - 6);
  const pageSize = Math.max(1, availableRows - (wrapped.length > availableRows ? 1 : 0));
  const offset = Math.min(Math.max(0, requestedOffset), Math.max(0, wrapped.length - pageSize));
  return { lines: wrapped.slice(offset, offset + pageSize), offset, pageSize, total: wrapped.length };
}

/** Bottom-panel selector with modal navigation. */
async function menu(
  ctx: ExtensionContext,
  title: string,
  labels: string[],
  allowBack: boolean,
): Promise<string | undefined> {
  if (ctx.mode !== "tui") {
    const selected = await ctx.ui.select(title, labels);
    if (!selected) throw new MenuCancelled();
    return selected;
  }

  const { Key, matchesKey } = await import("@earendil-works/pi-tui");
  const result = await ctx.ui.custom<{ action: "select"; value: string } | { action: "back" } | { action: "cancel" }>(
    (tui, theme, _keybindings, done) => {
      let selected = 0;
      let detailOffset = 0;
      let detailCount = 0;
      let detailPage = 1;


      return {
        render: (width) => {
          const viewport = detailViewport(title, width, tui.terminal.rows, labels.length, detailOffset);
          detailOffset = viewport.offset;
          detailCount = viewport.total;
          detailPage = viewport.pageSize;
          const visibleDetails = [...viewport.lines];
          if (detailOffset === 0 && visibleDetails[0]) visibleDetails[0] = theme.fg("accent", theme.bold(visibleDetails[0]));
          if (viewport.total > viewport.pageSize) {
            visibleDetails.push(theme.fg("muted", `details ${detailOffset + 1}–${Math.min(detailCount, detailOffset + detailPage)} of ${detailCount} · ctrl-u/ctrl-d scroll · g/G first/last`));
          }
          const rows = labels.map((label, index) => {
            const marker = index === selected ? "▶" : " ";
            const row = `${marker} ${label}`;
            return index === selected ? theme.fg("accent", row) : row;
          });
          return [
            ...visibleDetails,
            "",
            ...rows,
            "",
            theme.fg("muted", `↑↓/jk move · l/enter confirm${allowBack ? " · h back" : ""} · esc/ctrl-c cancel`),
          ];
        },
        invalidate: () => {},
        handleInput: (data) => {
          if (matchesKey(data, Key.escape) || matchesKey(data, Key.ctrl("c"))) done({ action: "cancel" });
          else if (allowBack && matchesKey(data, "h")) done({ action: "back" });
          else if (matchesKey(data, "l") || matchesKey(data, "enter")) done({ action: "select", value: labels[selected]! });
          else if (matchesKey(data, "j") || matchesKey(data, "down")) selected = Math.min(labels.length - 1, selected + 1);
          else if (matchesKey(data, "k") || matchesKey(data, "up")) selected = Math.max(0, selected - 1);
          else if (matchesKey(data, Key.ctrl("d"))) detailOffset = Math.min(Math.max(0, detailCount - detailPage), detailOffset + detailPage);
          else if (matchesKey(data, Key.ctrl("u"))) detailOffset = Math.max(0, detailOffset - detailPage);
          else if (matchesKey(data, "g")) detailOffset = 0;
          else if (data === "G") detailOffset = Math.max(0, detailCount - detailPage);
          tui.requestRender();
        },
      };
    },
    { overlay: false },
  );
  if (!result || result.action === "cancel") throw new MenuCancelled();
  return result.action === "back" ? undefined : result.value;
}

async function chooseScope(ctx: ExtensionContext, allowBack: boolean): Promise<PolicyScope | undefined> {
  const choice = await menu(ctx, "Choose bash-guard policy", ["Local project policy", "Global policy"], allowBack);
  if (choice === "Local project policy") return "local";
  if (choice === "Global policy") return "global";
  return undefined;
}

function ownershipSatisfies(actual: "read" | "edit" | "full", required: "edit" | "full"): boolean {
  return actual === "full" || (actual === "edit" && required === "edit");
}

async function grantOwnership(
  ctx: ExtensionContext,
  policy: PolicyStore,
  candidate: { path: string; required: "edit" | "full" },
): Promise<boolean> {
  const scope = await chooseScope(ctx, true);
  if (!scope) return false;
  let target: { path: string; line: number };
  try {
    target = policy.appendOwnership(scope, candidate.required, candidate.path);
  } catch (error) {
    const path = policy.getPolicyPath(scope);
    ctx.ui.notify(`Could not add the entry: ${String(error)}. Edit the policy manually.`, "warning");
    await openPolicyInEditor(ctx, path, 1);
    policy.reload();
    return ownershipSatisfies(policy.ownership(candidate.path), candidate.required);
  }
  await openPolicyInEditor(ctx, target.path, target.line);
  policy.reload();
  return ownershipSatisfies(policy.ownership(candidate.path), candidate.required);
}

async function trustReadOnlyTool(
  ctx: ExtensionContext,
  policy: PolicyStore,
  name: string,
): Promise<boolean> {
  const scope = await chooseScope(ctx, true);
  if (!scope) return false;
  let target: { path: string; line: number };
  try {
    target = policy.appendReadOnlyTool(scope, name);
  } catch (error) {
    const path = policy.getPolicyPath(scope);
    ctx.ui.notify(`Could not add the tool: ${String(error)}. Edit the policy manually.`, "warning");
    await openPolicyInEditor(ctx, path, 1);
    policy.reload();
    return policy.isReadOnlyTool(name);
  }
  await openPolicyInEditor(ctx, target.path, target.line);
  policy.reload();
  return policy.isReadOnlyTool(name);
}

async function refuseWithOptionalComment(ctx: ExtensionContext): Promise<PromptDecision> {
  const choice = await menu(ctx, "Command refused. Would you like to attach a comment?", ["Refuse without comment", "Add comment…"], false);
  if (choice !== "Add comment…") return { action: "refuse" };
  const context = await ctx.ui.input("Comment on refusal", "Explain why this command was refused");
  return { action: "refuse", ...(context?.trim() ? { context: context.trim() } : {}) };
}

async function promptFlow(
  ctx: ExtensionContext,
  policy: PolicyStore,
  analysis: Analysis,
  subject: string,
  readOnlyTool?: string,
): Promise<PromptDecision> {
  if (!ctx.hasUI) return { action: "refuse", context: "No interactive UI is available" };
  if (analysis.decision === "deny") {
    const choices = analysis.trashablePaths.length ? ["Refuse", "Move to trash instead"] : ["Refuse"];
    const choice = await menu(ctx, summary(analysis, subject), choices, false);
    return choice === "Move to trash instead" ? { action: "trash" } : refuseWithOptionalComment(ctx);
  }

  const candidate = analysis.ownershipCandidates.find((item) => !policy.isPolicyPath(item.path));
  while (true) {
    const choices = ["Allow once", "Refuse"];
    if (candidate) choices.push(`Grant ${candidate.required} ownership…`);
    const trustLabel = readOnlyTool ? `Trust ${readOnlyTool} as read-only…` : undefined;
    if (trustLabel) choices.push(trustLabel);
    const choice = await menu(ctx, summary(analysis, subject), choices, false);
    if (choice === "Allow once") return { action: "allow" };
    if (candidate && choice === `Grant ${candidate.required} ownership…`) {
      if (await grantOwnership(ctx, policy, candidate)) return { action: "allow" };
      continue;
    }
    if (trustLabel && readOnlyTool && choice === trustLabel) {
      if (await trustReadOnlyTool(ctx, policy, readOnlyTool)) return { action: "allow" };
      continue;
    }
    if (choice === "Refuse") return refuseWithOptionalComment(ctx);
  }
}

export async function promptForDecision(
  ctx: ExtensionContext,
  policy: PolicyStore,
  analysis: Analysis,
  subject: string,
  readOnlyTool?: string,
): Promise<PromptDecision> {
  try {
    return await promptFlow(ctx, policy, analysis, subject, readOnlyTool);
  } catch (error) {
    if (error instanceof MenuCancelled) return { action: "refuse" };
    throw error;
  }
}

export async function openPolicyManager(ctx: ExtensionCommandContext, policy: PolicyStore): Promise<void> {
  try {
    const scope = await chooseScope(ctx, false);
    if (!scope) return;
    const path = policy.ensurePolicy(scope);
    await openPolicyInEditor(ctx, path, 1);
    policy.reload();
  } catch (error) {
    if (!(error instanceof MenuCancelled)) throw error;
  }
}
