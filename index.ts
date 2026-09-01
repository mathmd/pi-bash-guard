import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import { quote as shellQuote } from "shell-quote";
import type { ExtensionAPI, ToolCallEvent, ToolResultEvent } from "@earendil-works/pi-coding-agent";
import { isToolCallEventType } from "@earendil-works/pi-coding-agent";
import { GuardAnalyzer, type CommandAnalysisUnit } from "./analyzer.ts";
import { canonicalPath, containsGitMetadata, pathExists, resolvePath } from "./path-utils.ts";
import { PolicyStore } from "./policy.ts";
import type { Analysis } from "./types.ts";
import { strongest } from "./types.ts";
import { openPolicyManager, promptForDecision } from "./ui.ts";
import { sendSystemNotification } from "./notifications.ts";
import { genericPathInputs } from "./tool-paths.ts";

const EXTENSION_DIR = dirname(fileURLToPath(import.meta.url));
interface PendingCreation { paths: string[]; reloadPolicy: boolean; }

function mergeAnalyses(items: Analysis[]): Analysis {
  return items.reduce<Analysis>((result, item) => ({
    decision: strongest(result.decision, item.decision),
    reasons: [...new Set([...result.reasons, ...item.reasons])],
    accesses: [...result.accesses, ...item.accesses],
    creationCandidates: [...new Set([...result.creationCandidates, ...item.creationCandidates])],
    trashablePaths: [...new Set([...result.trashablePaths, ...item.trashablePaths])],
    ownershipCandidates: [...result.ownershipCandidates, ...item.ownershipCandidates].filter((candidate, index, all) =>
      all.findIndex((other) => other.path === candidate.path && other.required === candidate.required) === index),
  }), { decision: "allow", reasons: [], accesses: [], creationCandidates: [], trashablePaths: [], ownershipCandidates: [] });
}

function analyzeTool(event: ToolCallEvent, cwd: string, analyzer: GuardAnalyzer, policy: PolicyStore): Analysis {
  if (isToolCallEventType("bash", event)) {
    return mergeAnalyses(analyzer.analyzeCommandUnits(event.input.command, cwd).map((unit) => unit.analysis));
  }
  if (isToolCallEventType("read", event)) return analyzer.analyzePathAccess(event.input.path, "read", cwd, "read");
  if (isToolCallEventType("write", event)) {
    const path = canonicalPath(resolvePath(event.input.path, cwd, policy.home));
    if (policy.isPolicyPath(path) || containsGitMetadata(path) || pathExists(path)) {
      return analyzer.analyzePathAccess(path, "edit", cwd, "write");
    }
    return { decision: "allow", reasons: [], accesses: [], creationCandidates: [path], trashablePaths: [], ownershipCandidates: [] };
  }
  if (isToolCallEventType("edit", event)) return analyzer.analyzePathAccess(event.input.path, "edit", cwd, "edit");
  if (isToolCallEventType("grep", event) || isToolCallEventType("find", event) || isToolCallEventType("ls", event)) {
    return analyzer.analyzePathAccess(event.input.path ?? ".", "read", cwd, event.toolName);
  }
  const paths = genericPathInputs(event.input, "", [], policy.isReadOnlyTool(event.toolName) ? "read" : undefined);
  if (!paths.length) return { decision: "allow", reasons: [], accesses: [], creationCandidates: [], trashablePaths: [], ownershipCandidates: [] };
  return mergeAnalyses(paths.map((item) => analyzer.analyzePathAccess(item.value, item.kind, cwd, event.toolName)));
}

function subjectFor(event: ToolCallEvent): string {
  if (isToolCallEventType("bash", event)) return `Command:\n${event.input.command}`;
  return `Tool: ${event.toolName}\nInput contains protected or unowned path access.`;
}

function executableBindingDetails(unit: CommandAnalysisUnit): string {
  if (!unit.executableBindings?.length) return "";
  const bindings = unit.executableBindings.map(({ name, value }) =>
    `$${name} = ${value === undefined ? "<unresolved at analysis time>" : JSON.stringify(value)}`);
  return `\n\nExecutable variable${bindings.length === 1 ? "" : "s"}:\n${bindings.join("\n")}`;
}

export default function bashGuard(pi: ExtensionAPI): void {
  let policy: PolicyStore | undefined;
  let analyzer: GuardAnalyzer | undefined;
  const pending = new Map<string, PendingCreation>();

  function configure(cwd: string, trustLocal: boolean): void {
    if (!policy) {
      policy = new PolicyStore(EXTENSION_DIR, cwd);
      analyzer = new GuardAnalyzer(policy);
    }
    policy.configure(cwd, trustLocal);
  }

  pi.registerCommand("bash-guard", {
    description: "Open the global or local bash-guard policy in your editor",
    handler: async (_args, ctx) => {
      configure(ctx.cwd, ctx.isProjectTrusted());
      await openPolicyManager(ctx, policy!);
    },
  });

  pi.on("session_start", async (_event, ctx) => {
    configure(ctx.cwd, ctx.isProjectTrusted());
    policy!.clearSessionOwnership();
    const issues = policy!.getIssues();
    if (issues.length) ctx.ui.notify(`bash-guard policy issue: ${issues.map((issue) => issue.message).join("; ")}`, "warning");
  });

  pi.on("tool_call", async (event, ctx) => {
    configure(ctx.cwd, ctx.isProjectTrusted());
    const analysis = analyzeTool(event, ctx.cwd, analyzer!, policy!);
    if (analysis.creationCandidates.length) {
      pending.set(event.toolCallId, {
        paths: analysis.creationCandidates.filter((path) => !existsSync(path)),
        reloadPolicy: analysis.creationCandidates.some((path) => policy!.isPolicyPath(path)),
      });
    }
    if (analysis.decision === "allow") return;

    let promptItems: Array<{ subject: string; analysis: Analysis; unitIndex?: number }>;
    if (isToolCallEventType("bash", event)) {
      const units = analyzer!.analyzeCommandUnits(event.input.command, ctx.cwd)
        .map((unit, unitIndex) => ({ ...unit, unitIndex }))
        .filter((unit) => unit.analysis.decision !== "allow");
      const combined = units.reduce((decision, unit) => strongest(decision, unit.analysis.decision), "allow" as Analysis["decision"]);
      promptItems = strongest(combined, analysis.decision) === combined
        ? units.map((unit, index) => ({
            subject: `Command requiring permission (${index + 1}/${units.length}, shell order):\n${unit.command}${executableBindingDetails(unit)}`,
            analysis: unit.analysis,
            unitIndex: unit.unitIndex,
          }))
        : [{ subject: subjectFor(event), analysis }];
    } else {
      promptItems = [{ subject: subjectFor(event), analysis }];
    }

    for (const item of promptItems) {
      const refreshedUnit = item.unitIndex !== undefined && isToolCallEventType("bash", event)
        ? analyzer!.analyzeCommandUnits(event.input.command, ctx.cwd)[item.unitIndex]
        : undefined;
      const itemAnalysis = refreshedUnit?.analysis ?? item.analysis;
      if (itemAnalysis.decision === "allow") continue;
      const promptAnalysis = promptItems.length > 1 && itemAnalysis.trashablePaths.length
        ? {
            ...itemAnalysis,
            trashablePaths: [],
            reasons: [...itemAnalysis.reasons, "Run this deletion separately to use reversible trash substitution"],
          }
        : itemAnalysis;
      if (ctx.mode === "tui" && ctx.hasUI) {
        sendSystemNotification("Pi requires permission", `${item.subject}\n${promptAnalysis.reasons.join("\n")}`);
      }
      const readOnlyTool = !isToolCallEventType("bash", event) &&
        itemAnalysis.accesses.some((access) => access.kind === "unknown" && access.source === event.toolName)
        ? event.toolName
        : undefined;
      const response = await promptForDecision(ctx, policy!, promptAnalysis, item.subject, readOnlyTool);
      if (response.action === "allow") continue;
      if (response.action === "trash" && isToolCallEventType("bash", event) && itemAnalysis.trashablePaths.length && promptItems.length === 1) {
        // Replace, rather than execute inside the hook, so Pi records the actual reversible operation.
        event.input.command = shellQuote(["gio", "trash", "--", ...itemAnalysis.trashablePaths]);
        pending.delete(event.toolCallId);
        return;
      }
      pending.delete(event.toolCallId);
      return {
        block: true,
        reason: `Blocked by bash-guard.${response.context ? ` User context: ${response.context}` : ""} ${itemAnalysis.reasons.join(" ")}`,
      };
    }
    return;
  });

  pi.on("tool_result", async (event: ToolResultEvent) => {
    const record = pending.get(event.toolCallId);
    pending.delete(event.toolCallId);
    if (!record || event.isError || !policy) return;
    for (const path of record.paths) if (pathExists(path)) policy.addCreated(path);
    if (record.reloadPolicy) policy.reload();
  });

  pi.on("agent_settled", async () => {
    policy?.clearRunOwnership();
    sendSystemNotification("Pi is idle", "The agent has finished and is waiting for input.");
  });
  pi.on("session_shutdown", async () => policy?.clearSessionOwnership());
}
