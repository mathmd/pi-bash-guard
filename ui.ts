import type { ExtensionCommandContext, ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { Analysis } from "./types.ts";
import type { PolicyScope, PolicyStore } from "./policy.ts";
import { openPolicyInEditor } from "./external-editor.ts";

export type PromptDecision = { action: "allow" | "refuse" | "trash"; context?: string };
class MenuCancelled extends Error {}

function summary(analysis: Analysis, subject: string): string {
  const reasons = analysis.reasons.map((reason) => `• ${reason}`).join("\n");
  return `${subject}\n\n${reasons}`.slice(0, 8_000);
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

      function titleLines(width: number): string[] {
        const available = Math.max(20, width - 2);
        const fitted: string[] = [];
        for (const source of title.split("\n")) {
          if (!source) {
            fitted.push("");
            continue;
          }
          for (let start = 0; start < source.length; start += available) fitted.push(source.slice(start, start + available));
        }
        if (fitted.length <= 12) return fitted;
        return [...fitted.slice(0, 11), theme.fg("muted", "…")];
      }

      return {
        render: (width) => {
          const heading = titleLines(width);
          if (heading[0]) heading[0] = theme.fg("accent", theme.bold(heading[0]));
          const rows = labels.map((label, index) => {
            const marker = index === selected ? "▶" : " ";
            const row = `${marker} ${label}`;
            return index === selected ? theme.fg("accent", row) : row;
          });
          return [
            ...heading,
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

async function refuseWithOptionalComment(ctx: ExtensionContext): Promise<PromptDecision> {
  const context = await ctx.ui.input("Comment on refusal (optional)", "Leave empty to refuse without a comment");
  return { action: "refuse", ...(context?.trim() ? { context: context.trim() } : {}) };
}

async function promptFlow(
  ctx: ExtensionContext,
  policy: PolicyStore,
  analysis: Analysis,
  subject: string,
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
    const choice = await menu(ctx, summary(analysis, subject), choices, false);
    if (choice === "Allow once") return { action: "allow" };
    if (candidate && choice === `Grant ${candidate.required} ownership…`) {
      if (await grantOwnership(ctx, policy, candidate)) return { action: "allow" };
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
): Promise<PromptDecision> {
  try {
    return await promptFlow(ctx, policy, analysis, subject);
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
