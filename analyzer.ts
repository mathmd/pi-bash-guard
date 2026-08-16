import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { parse as shellParse, type ParseToken } from "shell-quote";
import type { AccessKind, Analysis, CommandCategory, Decision, PathAccess } from "./types.ts";
import { strongest } from "./types.ts";
import { canonicalPath, containsGitMetadata, looksLikePath, pathExists, resolvePath } from "./path-utils.ts";
import type { PolicyStore } from "./policy.ts";
import { builtinCommandCategory, SHELL_CLOSING_WORDS, SHELL_HEADER_WORDS, SHELL_PREFIX_WORDS } from "./command-catalog.ts";

type OpToken = { op: string };
const CONTROL_OPS = new Set(["|", "|&", "&&", "||", ";", "&", "(", ")"]);
const REDIRECT_OPS = new Set([">", ">>", "1>", "1>>", "2>", "2>>", "&>", "<"]);
const INTERPRETERS = new Set(["bash", "sh", "zsh", "fish", "python", "python3", "node", "ruby", "perl", "deno", "bun"]);
const GIT_READ_SUBCOMMANDS = new Set(["status", "diff", "log", "show", "branch", "tag", "remote", "rev-parse", "ls-files", "grep", "blame", "describe", "shortlog"]);

const CATASTROPHIC: Array<[RegExp, string]> = [
  [/\b(?:mkfs(?:\.\w+)?|newfs_\w+|wipefs)\b/, "filesystem formatting or signature destruction"],
  [/\bdd\b[^\n]*\bof=\/dev\//, "raw device write"],
  [/\b(?:parted|fdisk|gdisk|sgdisk)\b/, "partition-table mutation"],
  [/\b(?:shutdown|reboot|halt|poweroff)\b/, "system power operation"],
  [/:\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:/, "fork bomb"],
  [/\bgit\s+push\b[^\n]*(?:--force(?:-with-lease)?|-f)(?:\s|$)/, "forced remote history rewrite"],
  [/\bgit\s+reset\b[^\n]*--hard\b/, "destructive Git reset"],
  [/\bgit\s+clean\b[^\n]*-[A-Za-z]*f/, "destructive removal of untracked files"],
  [/\bterraform\s+destroy\b|\btofu\s+destroy\b/, "infrastructure teardown"],
  [/\b(?:rm|rmdir)\b[^\n]*(?:\s|^)(?:\/|~)(?:\s|$)/, "deletion of a filesystem root or home"],
];

function isOp(token: ParseToken): token is OpToken {
  return typeof token === "object" && token !== null && "op" in token;
}

function commandName(value: string): string {
  return basename(value);
}

function cleanArgs(values: string[]): string[] {
  return values.filter((value) => !/^[A-Za-z_][A-Za-z0-9_]*=/.test(value));
}

function splitSegments(tokens: ParseToken[]): ParseToken[][] {
  const segments: ParseToken[][] = [];
  let current: ParseToken[] = [];
  for (const token of tokens) {
    if (isOp(token) && CONTROL_OPS.has(token.op)) {
      if (current.length) segments.push(current);
      current = [];
    } else current.push(token);
  }
  if (current.length) segments.push(current);
  return segments;
}
export class GuardAnalyzer {
  private readonly policy: PolicyStore;

  constructor(policy: PolicyStore) {
    this.policy = policy;
  }

  private path(raw: string, cwd: string): string {
    return canonicalPath(resolvePath(raw, cwd, this.policy.home));
  }

  analyzePathAccess(path: string, kind: AccessKind, cwd: string, source: string, literal = true): Analysis {
    return this.finalize([{ path: this.path(path, cwd), kind, source, literal }], [], [], []);
  }

  analyzeCommand(command: string, cwd: string): Analysis {
    for (const [pattern, reason] of CATASTROPHIC) {
      if (pattern.test(command)) return this.result("deny", [`Catastrophic operation: ${reason}`]);
    }

    let tokens: ParseToken[];
    try { tokens = shellParse(command.replace(/\n/g, " ; ")) as ParseToken[]; }
    catch { return this.result("ask", ["Shell syntax could not be analyzed safely"]); }

    const accesses: PathAccess[] = [];
    const creations: string[] = [];
    const trashable: string[] = [];
    const reasons: string[] = [];
    let baseDecision: Decision = "allow";

    for (const segment of splitSegments(tokens)) {
      const commandWords: string[] = [];
      for (let i = 0; i < segment.length; i++) {
        const token = segment[i];
        if (isOp(token) && REDIRECT_OPS.has(token.op)) {
          const target = segment[i + 1];
          if (typeof target === "string") {
            const path = this.path(target, cwd);
            if (token.op === "<") accesses.push({ path, kind: "read", source: "redirection", literal: true });
            else if (pathExists(path)) accesses.push({ path, kind: "edit", source: "redirection", literal: true, existed: true });
            else creations.push(path);
            i++;
          }
          continue;
        }
        if (typeof token === "string") commandWords.push(token);
      }
      const strings = cleanArgs(commandWords);
      if (!strings.length) continue;
      let index = 0;
      while (index < strings.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(strings[index])) index++;
      let word = commandName(strings[index] ?? "");
      if (SHELL_CLOSING_WORDS.has(word)) continue;
      if (SHELL_HEADER_WORDS.has(word)) {
        if (word === "while" || word === "until") index++;
        else continue;
      }
      while (SHELL_PREFIX_WORDS.has(commandName(strings[index] ?? ""))) index++;
      while (["env", "command", "exec", "nohup"].includes(commandName(strings[index] ?? ""))) {
        index++;
        while (strings[index]?.startsWith("-")) index++;
        while (/^[A-Za-z_][A-Za-z0-9_]*=/.test(strings[index] ?? "")) index++;
      }
      if (commandName(strings[index] ?? "") === "sudo") {
        baseDecision = strongest(baseDecision, "ask");
        reasons.push("Elevated execution requires approval");
        index++;
        while (strings[index]?.startsWith("-")) index++;
      }
      const executableRaw = strings[index];
      if (!executableRaw) continue;
      const cmd = commandName(executableRaw);
      const args = strings.slice(index + 1).filter((arg) => !REDIRECT_OPS.has(arg));

      if (cmd === "git") {
        const subIndex = args.findIndex((arg) => !arg.startsWith("-"));
        const sub = subIndex >= 0 ? args[subIndex] : "";
        const mutativeReadNamed =
          (sub === "branch" && args.some((arg) => /^-[dDmMcC]$/.test(arg))) ||
          (sub === "tag" && args.some((arg) => arg === "-d" || arg === "--delete")) ||
          (sub === "remote" && args.some((arg) => ["add", "remove", "rename", "set-url", "prune"].includes(arg)));
        if (!GIT_READ_SUBCOMMANDS.has(sub) || mutativeReadNamed) {
          baseDecision = strongest(baseDecision, "ask");
          reasons.push(`Mutative or unknown Git operation (${sub || "git"}) requires approval`);
        }
        continue;
      }

      if (cmd === "rm" || cmd === "rmdir" || cmd === "unlink") {
        for (const arg of args.filter((value) => !value.startsWith("-"))) {
          if (!looksLikePath(arg) && !pathExists(this.path(arg, cwd))) continue;
          const path = this.path(arg, cwd);
          accesses.push({ path, kind: "delete", source: cmd, literal: !/[*?$`]/.test(arg), existed: pathExists(path) });
          if (!/[*?$`]/.test(arg)) trashable.push(path);
        }
        continue;
      }

      if (["touch", "mkdir", "mktemp"].includes(cmd)) {
        for (const arg of args.filter((value) => !value.startsWith("-"))) {
          const path = this.path(arg, cwd);
          if (pathExists(path)) accesses.push({ path, kind: "edit", source: cmd, literal: true, existed: true });
          else creations.push(path);
        }
        continue;
      }

      if (cmd === "tee") {
        for (const arg of args.filter((value) => !value.startsWith("-"))) {
          const path = this.path(arg, cwd);
          if (pathExists(path)) accesses.push({ path, kind: "edit", source: "tee", literal: true, existed: true });
          else creations.push(path);
        }
        continue;
      }

      if (cmd === "cp" || cmd === "install") {
        const positional = args.filter((value) => !value.startsWith("-"));
        if (positional.length >= 2) {
          for (const src of positional.slice(0, -1)) accesses.push({ path: this.path(src, cwd), kind: "read", source: cmd, literal: true });
          const dest = this.path(positional.at(-1)!, cwd);
          if (pathExists(dest)) accesses.push({ path: dest, kind: "edit", source: cmd, literal: true, existed: true });
          else creations.push(dest);
        } else { baseDecision = strongest(baseDecision, "ask"); reasons.push(`Unable to resolve ${cmd} targets`); }
        continue;
      }

      if (cmd === "mv") {
        const positional = args.filter((value) => !value.startsWith("-"));
        for (const value of positional) accesses.push({ path: this.path(value, cwd), kind: "edit", source: cmd, literal: true, existed: pathExists(this.path(value, cwd)) });
        continue;
      }

      if (cmd === "find" && (args.includes("-delete") || args.includes("-exec") || args.includes("-execdir"))) {
        const root = args.find((arg) => !arg.startsWith("-")) ?? ".";
        if (args.includes("-delete")) {
          accesses.push({ path: this.path(root, cwd), kind: "delete", source: "find", literal: false, existed: pathExists(this.path(root, cwd)) });
        } else {
          baseDecision = strongest(baseDecision, "ask");
          reasons.push("find -exec/-execdir executes a nested command");
          accesses.push({ path: this.path(root, cwd), kind: "read", source: "find", literal: true });
        }
        continue;
      }

      if ((cmd === "sed" && args.some((arg) => arg === "-i" || arg.startsWith("-i"))) ||
          (cmd === "perl" && args.some((arg) => arg.includes("i")))) {
        for (const value of args.filter((arg) => !arg.startsWith("-") && looksLikePath(arg))) {
          accesses.push({ path: this.path(value, cwd), kind: "edit", source: cmd, literal: true, existed: pathExists(this.path(value, cwd)) });
        }
        continue;
      }

      if (INTERPRETERS.has(cmd)) {
        const cIndex = args.findIndex((arg) => arg === "-c" || arg === "-e");
        if (cIndex >= 0 && args[cIndex + 1]) {
          const nested = this.analyzeCommand(args[cIndex + 1], cwd);
          baseDecision = strongest(baseDecision, nested.decision);
          reasons.push(...nested.reasons);
          accesses.push(...nested.accesses);
          creations.push(...nested.creationCandidates);
          trashable.push(...nested.trashablePaths);
          continue;
        }
        const script = args.find((arg) => !arg.startsWith("-"));
        if (script) {
          const path = this.path(script, cwd);
          accesses.push({ path, kind: "execute", source: cmd, literal: true, existed: pathExists(path) });
          const screening = this.screenScript(path, cwd);
          if (screening) return this.result("deny", [`Prohibited script content: ${screening}`], accesses);
        } else { baseDecision = strongest(baseDecision, "ask"); reasons.push(`Opaque ${cmd} execution requires approval`); }
        continue;
      }

      if (executableRaw.includes("/")) {
        const executable = this.path(executableRaw, cwd);
        accesses.push({ path: executable, kind: "execute", source: "direct script", literal: true, existed: pathExists(executable) });
        const screening = this.screenScript(executable, cwd);
        if (screening) return this.result("deny", [`Prohibited script content: ${screening}`], accesses);
        continue;
      }

      const category = this.policy.commandCategory(cmd) ?? builtinCommandCategory(cmd);
      if (category) {
        const categorized = this.analyzeCategorizedCommand(category, cmd, args, cwd);
        baseDecision = strongest(baseDecision, categorized.decision);
        reasons.push(...categorized.reasons);
        accesses.push(...categorized.accesses);
        creations.push(...categorized.creationCandidates);
        trashable.push(...categorized.trashablePaths);
        continue;
      }

      baseDecision = strongest(baseDecision, "ask");
      reasons.push(`Unknown command ${cmd} requires approval`);
      for (const arg of args.filter((value) => looksLikePath(value) || pathExists(this.path(value, cwd)))) {
        accesses.push({ path: this.path(arg, cwd), kind: "unknown", source: cmd, literal: true });
      }
    }

    const finalized = this.finalize(accesses, creations, trashable, reasons);
    finalized.decision = strongest(finalized.decision, baseDecision);
    return finalized;
  }

  private analyzeCategorizedCommand(
    category: CommandCategory,
    command: string,
    args: string[],
    cwd: string,
  ): Analysis {
    if (category === "deny") return this.result("deny", [`Command ${command} is registered as prohibited`]);
    if (category === "allow") return this.result("allow", []);
    if (category === "remote") return this.result("ask", [`${command} may mutate remote or managed state`]);

    if (category === "execute" && (command === "eval" || command === "source" || command === ".")) {
      if (command === "eval") return this.analyzeCommand(args.join(" "), cwd);
      const script = args.find((arg) => !arg.startsWith("-"));
      return script
        ? this.analyzePathAccess(script, "execute", cwd, command)
        : this.result("ask", [`${command} requires an execution target`]);
    }

    const positional = args.filter((arg) => !arg.startsWith("-"));
    const pathArguments = positional.filter((arg) => looksLikePath(arg) || pathExists(this.path(arg, cwd)));
    if (category === "read") {
      return this.finalize(pathArguments.map((arg) => ({ path: this.path(arg, cwd), kind: "read", source: command, literal: true })), [], [], []);
    }
    if (category === "create") {
      const accesses: PathAccess[] = [];
      const creations: string[] = [];
      for (const arg of positional) {
        const path = this.path(arg, cwd);
        if (pathExists(path)) accesses.push({ path, kind: "edit", source: command, literal: true, existed: true });
        else creations.push(path);
      }
      return this.finalize(accesses, creations, [], []);
    }
    if (category === "edit") {
      return this.finalize(pathArguments.map((arg) => ({ path: this.path(arg, cwd), kind: "edit", source: command, literal: true })), [], [], []);
    }
    if (category === "delete") {
      const accesses = pathArguments.map((arg): PathAccess => ({ path: this.path(arg, cwd), kind: "delete", source: command, literal: !/[*?$`]/.test(arg) }));
      const trashable = accesses.filter((item) => item.literal).map((item) => item.path);
      return this.finalize(accesses, [], trashable, []);
    }
    // Execute-category tools may run arbitrary nested programs or build logic.
    const accesses = pathArguments.map((arg): PathAccess => ({ path: this.path(arg, cwd), kind: "execute", source: command, literal: true }));
    const result = this.finalize(accesses, [], [], [`${command} may execute arbitrary logic`]);
    result.decision = strongest(result.decision, "ask");
    return result;
  }

  private screenScript(path: string, cwd: string): string | undefined {
    if (!pathExists(path)) return undefined;
    try {
      const text = readFileSync(path, { encoding: "utf8", flag: "r" }).slice(0, 262_144);
      for (const [pattern, reason] of CATASTROPHIC) if (pattern.test(text)) return reason;
      const references = new Set<string>();
      for (const match of text.matchAll(/(?:~\/|\/|\.\.?\/)[^\s"'`;,|&()]+/g)) references.add(match[0]);
      for (const line of text.split("\n")) {
        if (line.trimStart().startsWith("#")) continue;
        try {
          for (const token of shellParse(line) as ParseToken[]) {
            if (typeof token === "string" && !token.startsWith("-")) references.add(token);
          }
        } catch { /* Non-shell source is covered by explicit path extraction above. */ }
      }
      for (const reference of references) {
        const candidate = this.path(reference, cwd);
        if ((looksLikePath(reference) || pathExists(candidate)) && this.policy.isSecret(candidate)) {
          return `secret reference ${candidate}`;
        }
      }
    } catch { /* Binary or unreadable executable: ownership still controls execution. */ }
    return undefined;
  }

  private finalize(accesses: PathAccess[], creations: string[], trashable: string[], reasons: string[]): Analysis {
    const safeCreations: string[] = [];
    for (const path of creations) {
      if (this.policy.isPolicyPath(path) || containsGitMetadata(path)) {
        accesses.push({ path, kind: "edit", source: "creation", literal: true, existed: false });
      } else safeCreations.push(path);
    }
    let decision: Decision = "allow";
    const ownershipCandidates: Analysis["ownershipCandidates"] = [];
    for (const access of accesses) {
      if (this.policy.isPolicyPath(access.path) && access.kind !== "read") {
        decision = strongest(decision, "ask");
        reasons.push(`Protected policy change requires approval: ${access.path}`);
        ownershipCandidates.push({ path: access.path, required: "edit" });
        continue;
      }
      if (this.policy.isSecret(access.path) && ["read", "execute", "unknown"].includes(access.kind)) {
        decision = "deny";
        reasons.push(`Secret access is prohibited: ${access.path}`);
        continue;
      }
      if (containsGitMetadata(access.path) && ["edit", "delete", "unknown"].includes(access.kind) && access.source !== "git") {
        decision = "deny";
        reasons.push(`Direct .git modification is prohibited: ${access.path}`);
        continue;
      }
      const ownership = this.policy.ownership(access.path);
      if (access.kind === "execute" && ownership !== "full") {
        decision = strongest(decision, "ask");
        reasons.push(`Execution requires full ownership or one-time approval: ${access.path}`);
        ownershipCandidates.push({ path: access.path, required: "full" });
      } else if (access.kind === "delete" && ownership === "read") {
        decision = "deny";
        reasons.push(`Permanent deletion of an unowned path is prohibited: ${access.path}`);
      } else if (["edit", "unknown"].includes(access.kind) && ownership === "read") {
        decision = strongest(decision, "ask");
        reasons.push(`Modification requires edit ownership or one-time approval: ${access.path}`);
        ownershipCandidates.push({ path: access.path, required: "edit" });
      } else if (access.kind === "remote") {
        decision = strongest(decision, "ask");
        reasons.push("Remote mutation requires one-time approval");
      }
    }
    return {
      decision,
      reasons: [...new Set(reasons)],
      accesses,
      creationCandidates: [...new Set(safeCreations)],
      trashablePaths: decision === "deny" ? [...new Set(trashable)] : [],
      ownershipCandidates: ownershipCandidates.filter((item, index, all) => all.findIndex((x) => x.path === item.path && x.required === item.required) === index),
    };
  }

  private result(decision: Decision, reasons: string[], accesses: PathAccess[] = []): Analysis {
    return { decision, reasons, accesses, creationCandidates: [], trashablePaths: [], ownershipCandidates: [] };
  }
}
