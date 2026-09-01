import { globSync, lstatSync, readFileSync, readdirSync } from "node:fs";
import { basename, join } from "node:path";
import { parse as shellParse, type ParseToken } from "shell-quote";
import type { AccessKind, Analysis, CommandCategory, Decision, PathAccess, PathExpansion } from "./types.ts";
import { strongest } from "./types.ts";
import { canonicalPath, containsGitMetadata, expandHome, looksLikePath, pathExists, pathIsDirectory, resolvePath } from "./path-utils.ts";
import type { PolicyStore } from "./policy.ts";
import { builtinCommandCategory, SHELL_CLOSING_WORDS, SHELL_HEADER_WORDS, SHELL_PREFIX_WORDS } from "./command-catalog.ts";

type OpToken = { op: string };
type GlobToken = { op: "glob"; pattern: string };
const CONTROL_OPS = new Set(["|", "|&", "&&", "||", ";", "&", "(", ")"]);
const REDIRECT_OPS = new Set([">", ">>", "1>", "1>>", "2>", "2>>", "&>", "&>>", ">&", "<&", "<<<", "<"]);
const INTERPRETERS = new Set(["bash", "sh", "zsh", "fish", "python", "python3", "node", "ruby", "perl", "lua", "luajit", "deno", "bun"]);
const SHELL_INTERPRETERS = new Set(["bash", "sh", "zsh", "fish"]);
const GIT_READ_SUBCOMMANDS = new Set([
  "status", "diff", "diff-files", "diff-index", "diff-tree", "log", "show", "rev-parse", "ls-files", "grep",
  "blame", "describe", "shortlog", "for-each-ref", "show-ref", "ls-tree", "cat-file", "name-rev", "rev-list",
  "merge-base", "count-objects", "whatchanged", "range-diff", "cherry", "verify-commit", "verify-tag", "version",
  "help", "check-ignore", "check-attr", "check-mailmap", "check-ref-format", "get-tar-commit-id", "patch-id", "var", "ls-remote",
]);
const GIT_GLOBAL_VALUE_OPTIONS = new Set(["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env", "--super-prefix"]);
const GIT_INFORMATION_OPTIONS = new Set(["--version", "-v", "--help", "-h", "--exec-path", "--html-path", "--man-path", "--info-path"]);

type GitInvocation = { subcommand: string; args: string[]; informational: boolean };

function parseGitInvocation(args: string[]): GitInvocation {
  let index = 0;
  let informational = false;
  while (index < args.length) {
    const arg = args[index]!;
    if (arg === "--") { index++; break; }
    if (!arg.startsWith("-")) break;
    if (GIT_INFORMATION_OPTIONS.has(arg) || [...GIT_INFORMATION_OPTIONS].some((option) => arg.startsWith(`${option}=`))) informational = true;
    if (GIT_GLOBAL_VALUE_OPTIONS.has(arg)) index += 2;
    else index++;
  }
  return { subcommand: args[index] ?? "", args: args.slice(index + 1), informational };
}

function isDestructiveGitInvocation(invocation: GitInvocation): boolean {
  return (invocation.subcommand === "push" && invocation.args.some((arg) => arg === "-f" || arg.startsWith("--force"))) ||
    (invocation.subcommand === "reset" && invocation.args.includes("--hard")) ||
    (invocation.subcommand === "clean" && invocation.args.some((arg) => /^-[A-Za-z]*f/.test(arg)));
}

function onlyOptions(args: string[], valueOptions: Set<string>): boolean {
  for (let index = 0; index < args.length; index++) {
    const arg = args[index]!;
    if (arg === "--") return index === args.length - 1;
    if (!arg.startsWith("-")) return false;
    if (valueOptions.has(arg)) index++;
  }
  return true;
}

function positionalAfterOptions(args: string[], valueOptions: Set<string>): string[] {
  const positional: string[] = [];
  for (let index = 0; index < args.length; index++) {
    const arg = args[index]!;
    if (arg === "--") {
      positional.push(...args.slice(index + 1));
      break;
    }
    if (valueOptions.has(arg)) index++;
    else if (!arg.startsWith("-")) positional.push(arg);
  }
  return positional;
}

function isReadOnlyGitOperation(invocation: GitInvocation): boolean {
  const { subcommand: sub, args } = invocation;
  if (invocation.informational) return true;
  if (!sub) return false;
  if (GIT_READ_SUBCOMMANDS.has(sub)) {
    if (args.some((arg) => arg === "--output" || arg.startsWith("--output=") || arg.startsWith("--open-files-in-pager"))) return false;
    return true;
  }
  if (sub === "branch") {
    if (args.some((arg) => ["-d", "-D", "-m", "-M", "-c", "-C", "--delete", "--move", "--copy", "--edit-description", "--set-upstream-to", "--unset-upstream"].includes(arg))) return false;
    return onlyOptions(args, new Set(["--contains", "--no-contains", "--merged", "--no-merged", "--points-at", "--format", "--sort", "--column"]));
  }
  if (sub === "tag") {
    if (args.some((arg) => ["-d", "--delete", "-f", "--force", "-a", "--annotate", "-s", "--sign"].includes(arg))) return false;
    return onlyOptions(args, new Set(["--contains", "--no-contains", "--merged", "--no-merged", "--points-at", "--format", "--sort", "--column"]));
  }
  if (sub === "remote") return args.length === 0 || args.every((arg) => arg === "-v" || arg === "--verbose") || ["show", "get-url"].includes(args[0] ?? "");
  if (sub === "stash") return ["list", "show"].includes(args[0] ?? "");
  if (sub === "worktree") return args[0] === "list";
  if (sub === "submodule") return ["status", "summary"].includes(args[0] ?? "status");
  if (sub === "notes") return ["list", "show"].includes(args[0] ?? "list");
  if (sub === "reflog") return ["show", "exists"].includes(args[0] ?? "show");
  if (sub === "config") {
    if (args.some((arg) => ["--add", "--replace-all", "--unset", "--unset-all", "--remove-section", "--rename-section", "--edit", "-e", "set", "unset", "rename-section", "remove-section"].includes(arg))) return false;
    const positional = positionalAfterOptions(args, new Set(["-f", "--file", "--blob", "--type", "--default"]));
    return positional.length <= 1 || ["get", "get-all", "get-regexp", "get-urlmatch", "list"].includes(positional[0] ?? "");
  }
  if (sub === "fsck") return !args.includes("--lost-found") && !args.includes("--write-commit-graph");
  return false;
}
const SYSTEMCTL_READ_SUBCOMMANDS = new Set([
  "status", "show", "cat", "list-units", "list-unit-files", "list-sockets", "list-timers", "list-dependencies",
  "list-jobs", "list-machines", "list-paths", "list-automounts", "is-active", "is-failed", "is-enabled",
  "is-system-running", "get-default", "help",
]);
const SYSTEMCTL_VALUE_OPTIONS = new Set([
  "-H", "--host", "-M", "--machine", "-t", "--type", "--state", "-p", "--property", "-n", "--lines",
  "-o", "--output", "--root", "--image", "--kill-whom", "--signal",
]);

function isReadOnlySystemctl(args: string[]): boolean {
  let index = 0;
  while (index < args.length && args[index]!.startsWith("-")) {
    const option = args[index++]!;
    if (["--version", "--help", "-h"].includes(option)) return true;
    if (SYSTEMCTL_VALUE_OPTIONS.has(option)) index++;
  }
  const subcommand = args[index] ?? "list-units";
  return SYSTEMCTL_READ_SUBCOMMANDS.has(subcommand);
}

const HYPRCTL_READ_COMMANDS = new Set([
  "activewindow", "activeworkspace", "animations", "binds", "clients", "configerrors", "cursorpos",
  "decorations", "descriptions", "devices", "getoption", "globalshortcuts", "instances", "layers", "layouts",
  "monitors", "rollinglog", "splash", "status", "systeminfo", "version", "workspacerules", "workspaces",
]);

function hyprctlCommand(args: string[]): string | undefined {
  for (let index = 0; index < args.length; index++) {
    const arg = args[index]!;
    if (arg === "--batch") return "--batch";
    if (["-i", "--instance"].includes(arg)) { index++; continue; }
    if (arg.startsWith("--instance=")) continue;
    if (arg.startsWith("-")) continue;
    return arg;
  }
  return undefined;
}

function isReadOnlyHyprctl(args: string[]): boolean {
  const command = hyprctlCommand(args);
  if (command === undefined && args.some((arg) => ["-h", "--help"].includes(arg))) return true;
  if (args.some((arg) => arg === "--batch" || arg.startsWith("--batch="))) return false;
  return command !== undefined && HYPRCTL_READ_COMMANDS.has(command);
}

function isReadOnlyNixStoreQuery(args: string[]): boolean {
  let query = false;
  if (args.length === 1 && ["-h", "--help", "--version"].includes(args[0]!)) return true;
  for (const arg of args) {
    if (["--force-realise", "--add-root"].includes(arg) || arg.startsWith("--add-root=")) return false;
    if (arg === "--query") query = true;
    else if (/^-[^-]*q/.test(arg)) query = true;
    if (/^-[^-]*f/.test(arg)) return false;
  }
  return query;
}

const NIX_READ_COMMANDS = new Set([
  "config show", "derivation show", "doctor", "log", "nar cat", "nar ls", "path-info",
  "profile list", "registry list", "show-config", "store cat", "store info", "store ls", "store ping", "why-depends",
]);
const NIX_GLOBAL_VALUE_OPTIONS = new Map<string, number>([
  ["--builders", 1], ["--connect-timeout", 1], ["--eval-store", 1], ["--extra-experimental-features", 1],
  ["--log-format", 1], ["--max-jobs", 1], ["--option", 2], ["--store", 1], ["--system", 1],
]);

function nixCliCommand(args: string[]): string {
  let index = 0;
  while (index < args.length && args[index]!.startsWith("-")) {
    const option = args[index++]!;
    index += NIX_GLOBAL_VALUE_OPTIONS.get(option) ?? 0;
  }
  const first = args[index] ?? "";
  if (["config", "derivation", "nar", "profile", "registry", "store"].includes(first)) {
    return `${first} ${args[index + 1] ?? ""}`.trim();
  }
  return first;
}

function isReadOnlyNixCli(args: string[]): boolean {
  const command = nixCliCommand(args);
  if (!command && args.some((arg) => ["-h", "--help", "--version"].includes(arg))) return true;
  return NIX_READ_COMMANDS.has(command);
}

interface CurlClassification {
  readOnly: boolean;
  outputs: string[];
}

function classifyCurl(args: string[]): CurlClassification {
  let method: string | undefined;
  let queryMode = false;
  let hasData = false;
  let mutativePayload = false;
  let opaqueConfig = false;
  const outputs: string[] = [];
  for (let index = 0; index < args.length; index++) {
    const arg = args[index]!;
    if (arg === "-G" || arg === "--get") queryMode = true;
    else if (arg === "-X" || arg === "--request") method = args[++index]?.toUpperCase();
    else if (arg.startsWith("--request=")) method = arg.slice("--request=".length).toUpperCase();
    else if (["-d", "--data", "--data-ascii", "--data-binary", "--data-raw", "--data-urlencode", "--json"].includes(arg)) {
      hasData = true; index++;
    } else if (/^-d.+/.test(arg) || /^--(?:data(?:-ascii|-binary|-raw|-urlencode)?|json)=/.test(arg)) hasData = true;
    else if (["-F", "--form", "--form-string", "-T", "--upload-file"].includes(arg)) {
      mutativePayload = true; index++;
    } else if (/^-F.+/.test(arg) || /^--(?:form|form-string|upload-file)=/.test(arg)) mutativePayload = true;
    else if (arg === "-K" || arg === "--config" || arg.startsWith("--config=")) {
      opaqueConfig = true;
      if (!arg.includes("=")) index++;
    } else if (arg === "-o" || arg === "--output") {
      const output = args[++index];
      if (output) outputs.push(output);
    } else if (arg.startsWith("--output=")) outputs.push(arg.slice("--output=".length));
    else if (/^-o.+/.test(arg)) outputs.push(arg.slice(2));
    else if (arg === "-O" || arg === "--remote-name" || arg === "--remote-header-name") opaqueConfig = true;
  }
  const safeMethod = !method || ["GET", "HEAD", "OPTIONS"].includes(method);
  return { readOnly: safeMethod && !mutativePayload && !opaqueConfig && (!hasData || queryMode), outputs };
}

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

function isGlob(token: ParseToken): token is GlobToken {
  return typeof token === "object" && token !== null && "op" in token && token.op === "glob" && "pattern" in token;
}

function commandName(value: string): string {
  return basename(value);
}

function cleanArgs(values: string[]): string[] {
  return values.filter((value) => !/^[A-Za-z_][A-Za-z0-9_]*=/.test(value));
}

function isLiteralShellPath(value: string): boolean {
  return !/\$(?:\(|\{|[A-Za-z_0-9])|`/.test(value);
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
export interface CommandAnalysisUnit {
  command: string;
  analysis: Analysis;
  executableBindings?: Array<{ name: string; value?: string }>;
  resolvedBindings?: Array<{ name: string; value: string }>;
}

/** Split top-level shell commands in lexical execution order without changing their source text. */
export function splitShellCommandUnits(command: string): string[] {
  const units: string[] = [];
  let start = 0;
  let quote: "'" | '"' | "`" | undefined;
  let escaped = false;
  let parentheses = 0;
  let comment = false;

  const push = (end: number) => {
    const value = command.slice(start, end).trim();
    if (value) units.push(value);
  };

  for (let index = 0; index < command.length; index++) {
    const char = command[index]!;
    if (comment) {
      if (char !== "\n") continue;
      comment = false;
    }
    if (escaped) { escaped = false; continue; }
    if (char === "\\" && quote !== "'") { escaped = true; continue; }
    if (quote) {
      if (char === quote) quote = undefined;
      continue;
    }
    if (char === "'" || char === '"' || char === "`") { quote = char; continue; }
    if (char === "#" && (index === 0 || /[\s;|&()]/.test(command[index - 1]!))) { comment = true; continue; }
    if (char === "(") { parentheses++; continue; }
    if (char === ")") { parentheses = Math.max(0, parentheses - 1); continue; }
    if (parentheses > 0) continue;

    const two = command.slice(index, index + 2);
    if (char === "&" && ([">", "<"].includes(command[index - 1] ?? "") || command[index + 1] === ">")) continue;
    const operatorLength = ["&&", "||", "|&", ";;"].includes(two) ? 2 : [";", "|", "&", "\n"].includes(char) ? 1 : 0;
    if (!operatorLength) continue;
    push(index);
    index += operatorLength - 1;
    start = index + 1;
  }
  push(command.length);
  return units.length ? units : [command.trim()].filter(Boolean);
}

type ShellEnvironment = Record<string, string>;

function shellEnvironmentResolver(environment: ShellEnvironment, home: string): (key: string) => string {
  return (key) => environment[key] ?? (key === "HOME" ? home : `$${key}`);
}

function persistentAssignmentUpdates(command: string, environment: ShellEnvironment, home: string): ShellEnvironment | undefined {
  let tokens: ParseToken[];
  try { tokens = shellParse(command, shellEnvironmentResolver(environment, home)) as ParseToken[]; }
  catch { return undefined; }
  const words = tokens.filter((token): token is string => typeof token === "string");
  if (words.length !== tokens.length) return undefined;
  const assignments = ["export", "readonly", "declare", "typeset"].includes(words[0] ?? "") ? words.slice(1) : words;
  if (!assignments.length) return undefined;
  const updates: ShellEnvironment = {};
  for (const assignment of assignments) {
    const match = assignment.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s);
    if (!match) return undefined;
    updates[match[1]!] = match[2]!;
  }
  return updates;
}

const MAX_GLOB_MATCHES = 512;

interface ShellGlobExpansion {
  argument: string;
  matches: string[];
  unresolved: boolean;
  truncated: boolean;
}

function expandShellGlob(pattern: string, cwd: string, home: string): ShellGlobExpansion {
  const argument = expandHome(pattern, home);
  if (!isStaticallyResolvedValue(argument)) return { argument, matches: [], unresolved: true, truncated: false };
  try {
    const allMatches = [...new Set(globSync(argument, { cwd }))].sort();
    return {
      argument,
      matches: allMatches.slice(0, MAX_GLOB_MATCHES),
      unresolved: false,
      truncated: allMatches.length > MAX_GLOB_MATCHES,
    };
  } catch {
    return { argument, matches: [], unresolved: true, truncated: false };
  }
}

interface StaticLoopBinding { name: string; values: string[]; }

function staticLoopBinding(command: string, environment: ShellEnvironment, home: string, cwd: string): StaticLoopBinding | undefined {
  if (referencedShellVariables(command).some((name) => name !== "HOME")) return undefined;
  let tokens: ParseToken[];
  try {
    tokens = shellParse(command.replace(/\\\r?\n/g, " "), shellEnvironmentResolver(environment, home)) as ParseToken[];
  } catch {
    return undefined;
  }
  const words: string[] = [];
  for (const token of tokens) {
    if (typeof token === "string") words.push(token);
    else if (isGlob(token)) {
      const expansion = expandShellGlob(token.pattern, cwd, home);
      if (expansion.unresolved || expansion.truncated) return undefined;
      words.push(...(expansion.matches.length ? expansion.matches : [expansion.argument]));
    } else return undefined;
  }
  let start = 0;
  while (SHELL_PREFIX_WORDS.has(words[start] ?? "")) start++;
  if (words[start] !== "for" || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(words[start + 1] ?? "") || words[start + 2] !== "in") return undefined;
  const values = words.slice(start + 3).filter((value) => value !== "do");
  if (!values.length || values.length > 128 || values.some((value) => /[{}]|\$[({A-Za-z_0-9]/.test(value))) return undefined;
  const concreteValues = values.map((value) => {
    const resolved = resolvePath(value, cwd, home);
    return looksLikePath(value) || pathExists(resolved) ? canonicalPath(resolved) : value;
  });
  return { name: words[start + 1]!, values: [...new Set(concreteValues)] };
}

function referencedShellVariables(command: string): string[] {
  const names = new Set<string>();
  try {
    shellParse(command, (name) => {
      names.add(name);
      return `$${name}`;
    });
  } catch {
    for (const match of command.matchAll(/\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))/g)) {
      names.add(match[1] ?? match[2]!);
    }
  }
  return [...names];
}

function isStaticallyResolvedValue(value: string): boolean {
  return !/\$(?:\(|\{|[A-Za-z_0-9])|`/.test(value);
}

interface MaskedCommandSubstitutions {
  command: string;
  sources: string[];
}

function closingParenthesis(source: string, start: number): number | undefined {
  let depth = 1;
  let quote: "'" | '"' | "`" | undefined;
  let escaped = false;
  for (let index = start; index < source.length; index++) {
    const character = source[index]!;
    if (escaped) { escaped = false; continue; }
    if (character === "\\" && quote !== "'") { escaped = true; continue; }
    if (quote) {
      if (character === quote) quote = undefined;
      continue;
    }
    if (character === "'" || character === '"' || character === "`") { quote = character; continue; }
    if (character === "(") depth++;
    else if (character === ")" && --depth === 0) return index;
  }
  return undefined;
}

function closingBacktick(source: string, start: number): number | undefined {
  let escaped = false;
  for (let index = start; index < source.length; index++) {
    const character = source[index]!;
    if (escaped) { escaped = false; continue; }
    if (character === "\\") { escaped = true; continue; }
    if (character === "`") return index;
  }
  return undefined;
}

/** Mask substitutions before shell-quote parsing; their contents are analyzed recursively as commands. */
function maskCommandSubstitutions(source: string): MaskedCommandSubstitutions {
  let command = "";
  const sources: string[] = [];
  let quote: "'" | '"' | undefined;
  for (let index = 0; index < source.length;) {
    const character = source[index]!;
    if (character === "\\" && quote !== "'") {
      command += source.slice(index, index + 2);
      index += 2;
      continue;
    }
    if (character === "'" || character === '"') {
      if (!quote) quote = character;
      else if (quote === character) quote = undefined;
      command += character;
      index++;
      continue;
    }
    if (quote !== "'" && source.startsWith("$(", index)) {
      const end = closingParenthesis(source, index + 2);
      if (end === undefined) { command += source.slice(index); break; }
      const arithmetic = source[index + 2] === "(";
      if (arithmetic) {
        const inner = source.slice(index + 3, Math.max(index + 3, end - 1));
        sources.push(...maskCommandSubstitutions(inner).sources);
      } else sources.push(source.slice(index + 2, end));
      command += `__bash_guard_substitution_${sources.length}__`;
      index = end + 1;
      continue;
    }
    if (quote !== "'" && character === "`") {
      const end = closingBacktick(source, index + 1);
      if (end === undefined) { command += source.slice(index); break; }
      sources.push(source.slice(index + 1, end));
      command += `__bash_guard_substitution_${sources.length}__`;
      index = end + 1;
      continue;
    }
    command += character;
    index++;
  }
  return { command, sources };
}

function hasOpaqueInlineCode(command: string, args: string[]): boolean {
  const valueFlags: Record<string, Set<string>> = {
    node: new Set(["-e", "--eval", "-p", "--print"]),
    python: new Set(["-c"]),
    python3: new Set(["-c"]),
    ruby: new Set(["-e"]),
    perl: new Set(["-e", "-E"]),
    lua: new Set(["-e"]),
    luajit: new Set(["-e"]),
    bun: new Set(["-e", "--eval", "-p", "--print"]),
  };
  const flags = valueFlags[command];
  for (const arg of args) {
    if (arg === "--") return false;
    if (!arg.startsWith("-")) return (command === "deno" || command === "bun") && arg === "eval";
    if (flags?.has(arg)) return true;
    if (flags && [...flags].some((flag) =>
      flag.startsWith("--") ? arg.startsWith(`${flag}=`) : arg.startsWith(flag) && arg.length > flag.length)) return true;
  }
  return false;
}

function recursiveCopyTargets(source: string, destination: string, limit = 10_000): string[] {
  const targets: string[] = [];
  const walk = (sourcePath: string, destinationPath: string): void => {
    if (targets.length >= limit) throw new Error("copy target limit exceeded");
    const stat = lstatSync(sourcePath);
    if (!stat.isDirectory()) {
      targets.push(destinationPath);
      return;
    }
    if (!pathExists(destinationPath)) targets.push(destinationPath);
    for (const entry of readdirSync(sourcePath)) walk(join(sourcePath, entry), join(destinationPath, entry));
  };
  try {
    walk(source, destination);
    return targets;
  } catch {
    return [destination];
  }
}

export class GuardAnalyzer {
  private readonly policy: PolicyStore;

  constructor(policy: PolicyStore) {
    this.policy = policy;
  }

  private path(raw: string, cwd: string): string {
    return canonicalPath(resolvePath(raw, cwd, this.policy.home));
  }

  private executableVariableNames(command: string, cwd: string, environment: ShellEnvironment): string[] {
    const executableNames: string[] = [];
    for (const name of referencedShellVariables(command)) {
      const marker = `__bash_guard_variable_${name}__`;
      const probe = this.analyzeCommand(command, cwd, { ...environment, [name]: marker });
      const isCommand = probe.reasons.some((reason) => reason.startsWith("Unknown command ") && reason.includes(marker));
      const isExecutionTarget = probe.accesses.some((access) => access.kind === "execute" &&
        (access.source?.includes(marker) || access.path.includes(marker)));
      if (isCommand || isExecutionTarget) executableNames.push(name);
    }
    return executableNames;
  }

  analyzeCommandUnits(command: string, cwd: string): CommandAnalysisUnit[] {
    const environment: ShellEnvironment = {};
    const candidates = new Map<string, string[]>();
    const loops: Array<{ name: string; values: string[]; previous?: string[] }> = [];
    const results: CommandAnalysisUnit[] = [];
    for (const unit of splitShellCommandUnits(command)) {
      const loop = staticLoopBinding(unit, environment, this.policy.home, cwd);
      if (loop) {
        results.push({ command: unit, analysis: this.analyzeCommand(unit, cwd, environment) });
        loops.push({ name: loop.name, values: loop.values, previous: candidates.get(loop.name) });
        candidates.set(loop.name, loop.values);
        continue;
      }

      const referencedNames = referencedShellVariables(unit);
      const executableNames = this.executableVariableNames(unit, cwd, environment);
      const expansionNames = [...new Set([...executableNames, ...referencedNames.filter((name) => candidates.has(name))])];
      let contexts: Array<{ environment: ShellEnvironment; bindings: Array<{ name: string; value?: string }> }> = [
        { environment: { ...environment }, bindings: [] },
      ];
      let expansionLimited = false;
      for (const name of expansionNames) {
        const assigned = environment[name];
        const values: Array<string | undefined> = candidates.get(name) ??
          (assigned !== undefined && isStaticallyResolvedValue(assigned)
            ? [assigned]
            : name === "HOME" ? [this.policy.home] : [undefined]);
        if (contexts.length * values.length > 128) {
          expansionLimited = true;
          const unresolvedEnvironment = { ...environment };
          for (const variable of expansionNames) delete unresolvedEnvironment[variable];
          contexts = [{
            environment: unresolvedEnvironment,
            bindings: expansionNames.map((variable) => ({ name: variable })),
          }];
          break;
        }
        contexts = contexts.flatMap((context) => values.map((value) => {
          const resolvedEnvironment = { ...context.environment };
          if (value === undefined) delete resolvedEnvironment[name];
          else resolvedEnvironment[name] = value;
          return {
            environment: resolvedEnvironment,
            bindings: [...context.bindings, { name, ...(value === undefined ? {} : { value }) }],
          };
        }));
      }

      for (const context of contexts) {
        const analysis = this.analyzeCommand(unit, cwd, context.environment);
        if (expansionLimited) {
          analysis.decision = strongest(analysis.decision, "ask");
          analysis.reasons.push("Static variable expansion has more than 128 candidate combinations and cannot be analyzed safely");
        }
        const resolvedBindings = referencedNames.flatMap((name) => {
          const value = context.environment[name] ?? (name === "HOME" ? this.policy.home : undefined);
          return value !== undefined && isStaticallyResolvedValue(value) ? [{ name, value }] : [];
        });
        results.push({
          command: unit,
          analysis,
          ...(context.bindings.some(({ name }) => executableNames.includes(name))
            ? { executableBindings: context.bindings.filter(({ name }) => executableNames.includes(name)) }
            : {}),
          ...(resolvedBindings.length ? { resolvedBindings } : {}),
        });
      }

      const updates = persistentAssignmentUpdates(unit, environment, this.policy.home);
      if (updates) {
        Object.assign(environment, updates);
        for (const name of Object.keys(updates)) candidates.delete(name);
      }
      if (/^done(?:\s|$)/.test(unit.trim())) {
        const closed = loops.pop();
        if (closed) {
          environment[closed.name] = closed.values.at(-1)!;
          if (closed.previous) candidates.set(closed.name, closed.previous);
          else candidates.delete(closed.name);
        }
      }
    }
    return results;
  }

  analyzePathAccess(path: string, kind: AccessKind, cwd: string, source: string, literal = true): Analysis {
    const lexicalPath = resolvePath(path, cwd, this.policy.home);
    if (["read", "edit"].includes(kind) && this.policy.isSafeProcessIoPath(lexicalPath)) return this.result("allow", []);
    return this.finalize([{ path: this.path(path, cwd), kind, source, literal }], [], [], []);
  }

  analyzeCommand(command: string, cwd: string, shellEnvironment: ShellEnvironment = {}): Analysis {
    for (const [pattern, reason] of CATASTROPHIC) {
      if (pattern.test(command)) return this.result("deny", [`Catastrophic operation: ${reason}`]);
    }

    const substitutions = maskCommandSubstitutions(command);
    let tokens: ParseToken[];
    try {
      const normalizedCommand = substitutions.command.replace(/\\\r?\n/g, " ").replace(/\n/g, " ; ");
      tokens = shellParse(normalizedCommand, shellEnvironmentResolver(shellEnvironment, this.policy.home)) as ParseToken[];
    }
    catch { return this.result("ask", ["Shell syntax could not be analyzed safely"]); }

    const accesses: PathAccess[] = [];
    const creations: string[] = [];
    const trashable: string[] = [];
    const reasons: string[] = [];
    const unknownCommands: NonNullable<Analysis["unknownCommands"]> = [];
    let baseDecision: Decision = "allow";
    const pathExpansions: PathExpansion[] = [];
    const unmatchedGlobArguments = new Set<string>();
    const unresolvedPathArguments = new Set<string>();

    for (const source of substitutions.sources) {
      const nested = this.analyzeCommand(source, cwd, shellEnvironment);
      baseDecision = strongest(baseDecision, nested.decision);
      reasons.push(...nested.reasons);
      accesses.push(...nested.accesses);
      creations.push(...nested.creationCandidates);
      trashable.push(...nested.trashablePaths);
      unknownCommands.push(...(nested.unknownCommands ?? []));
      pathExpansions.push(...(nested.pathExpansions ?? []));
    }
    for (const segment of splitSegments(tokens)) {
      const commandWords: string[] = [];
      for (let i = 0; i < segment.length; i++) {
        const token = segment[i];
        if (isGlob(token)) {
          const expansion = expandShellGlob(token.pattern, cwd, this.policy.home);
          pathExpansions.push({
            expression: token.pattern,
            matches: expansion.matches.map((match) => this.path(match, cwd)),
            ...(expansion.unresolved ? { unresolved: true } : {}),
            ...(expansion.truncated ? { truncated: true } : {}),
          });
          if (expansion.unresolved || expansion.truncated) {
            unresolvedPathArguments.add(expansion.argument);
            baseDecision = strongest(baseDecision, "ask");
            reasons.push(expansion.truncated
              ? `Wildcard path has more than ${MAX_GLOB_MATCHES} matches and cannot be analyzed completely: ${token.pattern}`
              : `Dynamic path cannot be resolved statically: ${token.pattern}`);
            commandWords.push(expansion.argument);
          } else if (expansion.matches.length) commandWords.push(...expansion.matches);
          else {
            unmatchedGlobArguments.add(expansion.argument);
            commandWords.push(expansion.argument);
          }
          continue;
        }
        if (isOp(token) && REDIRECT_OPS.has(token.op)) {
          const target = segment[i + 1];
          if (typeof target === "string") {
            const descriptorTarget = [">&", "<&"].includes(token.op) && /^(?:\d+|-)$/.test(target);
            const lexicalPath = resolvePath(target, cwd, this.policy.home);
            if (token.op !== "<<<" && !descriptorTarget && !this.policy.isSafeProcessIoPath(lexicalPath)) {
              const path = this.path(target, cwd);
              if (token.op === "<") accesses.push({ path, kind: "read", source: "redirection", literal: isLiteralShellPath(target) });
              else if (pathExists(path)) accesses.push({ path, kind: "edit", source: "redirection", literal: isLiteralShellPath(target), existed: true });
              else creations.push(path);
            }
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
      while (SHELL_PREFIX_WORDS.has(commandName(strings[index] ?? ""))) index++;
      let word = commandName(strings[index] ?? "");
      if (SHELL_CLOSING_WORDS.has(word)) continue;
      if (SHELL_HEADER_WORDS.has(word)) {
        if (word === "while" || word === "until") {
          index++;
          while (SHELL_PREFIX_WORDS.has(commandName(strings[index] ?? ""))) index++;
          word = commandName(strings[index] ?? "");
          if (SHELL_CLOSING_WORDS.has(word) || SHELL_HEADER_WORDS.has(word)) continue;
        } else continue;
      }
      if (commandName(strings[index] ?? "") === "command") {
        let optionIndex = index + 1;
        let inspection = false;
        let recognizedOptions = true;
        while (strings[optionIndex]?.startsWith("-")) {
          const option = strings[optionIndex++]!;
          if (option === "--") break;
          if (!/^-[pVv]+$/.test(option)) recognizedOptions = false;
          if (/[Vv]/.test(option)) inspection = true;
        }
        if (recognizedOptions && inspection) continue;
      }
      while (true) {
        const wrapper = commandName(strings[index] ?? "");
        if (wrapper === "timeout") {
          index++;
          while (strings[index]?.startsWith("-")) {
            const option = strings[index++]!;
            if (["-k", "--kill-after", "-s", "--signal"].includes(option)) index++;
            if (option === "--") break;
          }
          if (strings[index]) index++; // duration
          continue;
        }
        if (!["env", "command", "exec", "nohup"].includes(wrapper)) break;
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
      for (const arg of args) {
        if (isStaticallyResolvedValue(arg) || !arg.includes("/") || /^(?:[A-Za-z][A-Za-z0-9+.-]*):\/\//.test(arg) || unresolvedPathArguments.has(arg)) continue;
        unresolvedPathArguments.add(arg);
        baseDecision = strongest(baseDecision, "ask");
        reasons.push(`Dynamic path cannot be resolved statically: ${arg}`);
        pathExpansions.push({ expression: arg, matches: [], unresolved: true });
      }
      const pathLikeArgument = (value: string): boolean => !unresolvedPathArguments.has(value) &&
        (unmatchedGlobArguments.has(value) || looksLikePath(value) || pathExists(this.path(value, cwd)));
      const argumentAccess = (value: string, kind: AccessKind, source: string): PathAccess => {
        const unmatched = unmatchedGlobArguments.has(value);
        const path = this.path(value, cwd);
        return { path, kind, source, literal: unmatched || isLiteralShellPath(value), existed: unmatched ? false : pathExists(path) };
      };

      const gitInvocation = cmd === "git" ? parseGitInvocation(args) : undefined;
      if (gitInvocation && isDestructiveGitInvocation(gitInvocation)) {
        return this.result("deny", [`Destructive Git operation (${gitInvocation.subcommand}) is prohibited`]);
      }
      if (cmd === "git") {
        const invocation = gitInvocation!;
        const readOnly = isReadOnlyGitOperation(invocation);
        if (!readOnly) {
          baseDecision = strongest(baseDecision, "ask");
          reasons.push(`Mutative or unknown Git operation (${invocation.subcommand || "git"}) requires approval`);
        } else {
          let afterSeparator = false;
          for (const arg of invocation.args) {
            if (arg === "--") { afterSeparator = true; continue; }
            if (arg.startsWith("-")) continue;
            const colon = ["show", "cat-file", "diff", "log"].includes(invocation.subcommand) ? arg.indexOf(":") : -1;
            const rawPath = colon >= 0 ? arg.slice(colon + 1) : arg;
            const candidate = this.path(rawPath, cwd);
            if ((colon >= 0 || afterSeparator || rawPath.startsWith(".") || looksLikePath(rawPath) || pathExists(candidate)) && this.policy.isSecret(candidate)) {
              accesses.push({ path: candidate, kind: "read", source: "git", literal: true, existed: pathExists(candidate) });
            }
          }
        }
        continue;
      }
      if (cmd === "nix" && isReadOnlyNixCli(args)) {
        const categorized = this.analyzeCategorizedCommand("read", cmd, args, cwd, shellEnvironment, unmatchedGlobArguments, unresolvedPathArguments);
        baseDecision = strongest(baseDecision, categorized.decision);
        reasons.push(...categorized.reasons);
        accesses.push(...categorized.accesses);
        continue;
      }

      if (cmd === "nix-store" && isReadOnlyNixStoreQuery(args)) {
        const categorized = this.analyzeCategorizedCommand("read", cmd, args, cwd, shellEnvironment, unmatchedGlobArguments, unresolvedPathArguments);
        baseDecision = strongest(baseDecision, categorized.decision);
        reasons.push(...categorized.reasons);
        accesses.push(...categorized.accesses);
        continue;
      }

      if (cmd === "hyprctl") {
        if (!isReadOnlyHyprctl(args)) {
          baseDecision = strongest(baseDecision, "ask");
          reasons.push(`Mutative or unknown hyprctl command (${hyprctlCommand(args) ?? "hyprctl"}) requires approval`);
        }
        continue;
      }


      if (cmd === "curl") {
        const classification = classifyCurl(args);
        if (!classification.readOnly) {
          baseDecision = strongest(baseDecision, "ask");
          reasons.push("curl request may mutate remote state or uses opaque output options");
        }
        for (const output of classification.outputs) {
          if (output === "-") continue;
          const lexicalOutput = resolvePath(output, cwd, this.policy.home);
          if (this.policy.isSafeProcessIoPath(lexicalOutput)) continue;
          const path = this.path(output, cwd);
          if (pathExists(path)) accesses.push({ path, kind: "edit", source: "curl output", literal: true, existed: true });
          else creations.push(path);
        }
        continue;
      }

      if (cmd === "ipptool") {
        const candidates = args.filter((arg) =>
          !arg.startsWith("-") && !/^(?:ipps?|https?):\/\//i.test(arg) &&
          (/\.test$/i.test(arg) || looksLikePath(arg) || pathExists(this.path(arg, cwd))));
        const safeQuery = !args.includes("-") && candidates.every((arg) => /^(?:get|list|identify|validate)[\w-]*\.test$/i.test(basename(arg)));
        if (!safeQuery) {
          baseDecision = strongest(baseDecision, "ask");
          reasons.push("ipptool test may perform a mutative printer operation");
        }
        for (const arg of candidates.filter((value) => looksLikePath(value) || pathExists(this.path(value, cwd)))) {
          accesses.push({ path: this.path(arg, cwd), kind: "read", source: "ipptool", literal: isLiteralShellPath(arg) });
        }
        continue;
      }

      if (cmd === "systemctl") {
        if (!isReadOnlySystemctl(args)) {
          baseDecision = strongest(baseDecision, "ask");
          reasons.push("Mutative or unknown systemctl operation requires approval");
        }
        continue;
      }

      if (cmd === "rm" || cmd === "rmdir" || cmd === "unlink") {
        for (const arg of args.filter((value) => !value.startsWith("-") && pathLikeArgument(value))) {
          const access = argumentAccess(arg, "delete", cmd);
          accesses.push(access);
          if (access.literal) trashable.push(access.path);
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
          const sourceArgs = positional.slice(0, -1);
          const destinationArg = positional.at(-1)!;
          for (const source of sourceArgs) {
            accesses.push({ path: this.path(source, cwd), kind: "read", source: cmd, literal: isLiteralShellPath(source) });
          }
          const destination = this.path(destinationArg, cwd);
          const destinationIsDirectory = sourceArgs.length > 1 || /[/\\]$/.test(destinationArg) || pathIsDirectory(destination);
          const baseTargets = destinationIsDirectory
            ? sourceArgs.map((source) => canonicalPath(join(destination, basename(source))))
            : [destination];
          const recursive = args.some((arg) => arg === "--recursive" || /^-[^-]*[Rr]/.test(arg));
          const targets = sourceArgs.flatMap((source, index) => recursive
            ? recursiveCopyTargets(this.path(source, cwd), baseTargets[index] ?? destination)
            : [baseTargets[index] ?? destination]);
          for (const target of targets) {
            if (pathExists(target)) accesses.push({ path: target, kind: "edit", source: cmd, literal: true, existed: true });
            else creations.push(target);
          }
        } else {
          baseDecision = strongest(baseDecision, "ask");
          reasons.push(`Unable to resolve ${cmd} targets`);
        }
        continue;
      }

      if (cmd === "mv") {
        const positional = args.filter((value) => !value.startsWith("-"));
        for (const value of positional) accesses.push({ path: this.path(value, cwd), kind: "edit", source: cmd, literal: isLiteralShellPath(value), existed: pathExists(this.path(value, cwd)) });
        continue;
      }

      if (cmd === "find" && args.some((arg) => ["-delete", "-exec", "-execdir", "-ok", "-okdir"].includes(arg))) {
        const root = args[0] && !args[0].startsWith("-") ? args[0] : ".";
        if (args.includes("-delete")) {
          accesses.push({ path: this.path(root, cwd), kind: "delete", source: "find", literal: false, existed: pathExists(this.path(root, cwd)) });
        } else {
          baseDecision = strongest(baseDecision, "ask");
          reasons.push("find -exec/-execdir/-ok/-okdir executes a nested command");
          accesses.push({ path: this.path(root, cwd), kind: "read", source: "find", literal: isLiteralShellPath(root) });
        }
        continue;
      }

      const perlInPlace = cmd === "perl" && args.some((arg) => /^-[^-]*i/.test(arg) || arg === "--in-place" || arg.startsWith("--in-place="));
      if ((cmd === "sed" && args.some((arg) => arg === "-i" || arg.startsWith("-i"))) || perlInPlace) {
        for (const value of args.filter((arg) => !arg.startsWith("-") && looksLikePath(arg))) {
          accesses.push({ path: this.path(value, cwd), kind: "edit", source: cmd, literal: isLiteralShellPath(value), existed: pathExists(this.path(value, cwd)) });
        }
        if (cmd === "sed") continue;
      }

      const luacParseOnly = cmd === "luac" && args.some((arg) => arg === "-p" || /^-[^-]*p/.test(arg)) &&
        !args.some((arg) => arg === "-o" || arg.startsWith("--output"));
      if (luacParseOnly) {
        const categorized = this.analyzeCategorizedCommand("read", cmd, args, cwd, shellEnvironment, unmatchedGlobArguments, unresolvedPathArguments);
        baseDecision = strongest(baseDecision, categorized.decision);
        reasons.push(...categorized.reasons);
        accesses.push(...categorized.accesses);
        continue;
      }

      if (INTERPRETERS.has(cmd)) {
        if (SHELL_INTERPRETERS.has(cmd)) {
          const cIndex = args.findIndex((arg) => arg === "-c" || /^-[^-]*c/.test(arg));
          if (cIndex >= 0) {
            const source = args[cIndex + 1];
            if (source) {
              const nested = this.analyzeCommand(source, cwd, shellEnvironment);
              baseDecision = strongest(baseDecision, nested.decision);
              reasons.push(...nested.reasons);
              accesses.push(...nested.accesses);
              creations.push(...nested.creationCandidates);
              trashable.push(...nested.trashablePaths);
              unknownCommands.push(...(nested.unknownCommands ?? []));
            } else {
              baseDecision = strongest(baseDecision, "ask");
              reasons.push(`Shell interpreter ${cmd} has an unresolved inline command`);
            }
            continue;
          }
        } else if (hasOpaqueInlineCode(cmd, args)) {
          baseDecision = strongest(baseDecision, "ask");
          reasons.push(`Opaque ${cmd} inline code requires approval`);
          continue;
        }
        const script = args.find((arg) => !arg.startsWith("-"));
        if (script) {
          const path = this.path(script, cwd);
          accesses.push({ path, kind: "execute", source: cmd, literal: isLiteralShellPath(script), existed: pathExists(path) });
          const screening = this.screenScript(path, cwd);
          if (screening) return this.result("deny", [`Prohibited script content: ${screening}`], accesses);
        } else { baseDecision = strongest(baseDecision, "ask"); reasons.push(`Opaque ${cmd} execution requires approval`); }
        continue;
      }

      if (executableRaw.includes("/")) {
        const executable = this.path(executableRaw, cwd);
        const screening = this.screenScript(executable, cwd);
        if (screening) return this.result("deny", [`Prohibited script content: ${screening}`]);
        if (this.policy.isSystemReadonlyPath(executable)) {
          const systemCategory = builtinCommandCategory(cmd);
          if (!systemCategory) {
            baseDecision = strongest(baseDecision, "ask");
            reasons.push(`Unknown system command ${cmd} requires approval`);
          } else {
            const categorized = this.analyzeCategorizedCommand(systemCategory, cmd, args, cwd, shellEnvironment, unmatchedGlobArguments, unresolvedPathArguments);
            baseDecision = strongest(baseDecision, categorized.decision);
            reasons.push(...categorized.reasons);
            accesses.push(...categorized.accesses);
            creations.push(...categorized.creationCandidates);
            trashable.push(...categorized.trashablePaths);
          }
          continue;
        }
        accesses.push({ path: executable, kind: "execute", source: "direct script", literal: isLiteralShellPath(executableRaw), existed: pathExists(executable) });
        continue;
      }

      const category = builtinCommandCategory(cmd);
      if (category) {
        const categorized = this.analyzeCategorizedCommand(category, cmd, args, cwd, shellEnvironment, unmatchedGlobArguments, unresolvedPathArguments);
        baseDecision = strongest(baseDecision, categorized.decision);
        reasons.push(...categorized.reasons);
        accesses.push(...categorized.accesses);
        creations.push(...categorized.creationCandidates);
        trashable.push(...categorized.trashablePaths);
        continue;
      }

      if (this.policy.isTrustedCommand(cmd, args)) {
        for (const arg of args.filter(pathLikeArgument)) {
          accesses.push(argumentAccess(arg, "unknown", cmd));
        }
        continue;
      }

      baseDecision = strongest(baseDecision, "ask");
      unknownCommands.push({ name: cmd, arguments: args });
      const unresolvedVariables = [...executableRaw.matchAll(/\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))/g)]
        .map((match) => `$${match[1] ?? match[2]}`);
      reasons.push(unresolvedVariables.length
        ? `Executable variable ${[...new Set(unresolvedVariables)].join(", ")} cannot be resolved statically; runtime command requires approval`
        : `Unknown command ${cmd} requires approval`);
      for (const arg of args.filter(pathLikeArgument)) {
        accesses.push(argumentAccess(arg, "unknown", cmd));
      }
    }

    const finalized = this.finalize(accesses, creations, trashable, reasons);
    finalized.decision = strongest(finalized.decision, baseDecision);
    if (unknownCommands.length) finalized.unknownCommands = unknownCommands.filter((item, index, all) =>
      all.findIndex((candidate) => candidate.name === item.name &&
        candidate.arguments.length === item.arguments.length &&
        candidate.arguments.every((value, argIndex) => value === item.arguments[argIndex])) === index);
    if (pathExpansions.length) finalized.pathExpansions = pathExpansions.filter((item, index, all) =>
      all.findIndex((candidate) => candidate.expression === item.expression &&
        candidate.unresolved === item.unresolved && candidate.truncated === item.truncated &&
        candidate.matches.length === item.matches.length && candidate.matches.every((value, matchIndex) => value === item.matches[matchIndex])) === index);
    return finalized;
  }

  private analyzeCategorizedCommand(
    category: CommandCategory,
    command: string,
    args: string[],
    cwd: string,
    shellEnvironment: ShellEnvironment,
    unmatchedGlobArguments = new Set<string>(),
    unresolvedPathArguments = new Set<string>(),
  ): Analysis {
    if (category === "deny") return this.result("deny", [`Command ${command} is registered as prohibited`]);
    if (category === "allow") return this.result("allow", []);
    if (category === "remote") return this.result("ask", [`${command} may mutate remote or managed state`]);

    if (category === "execute" && (command === "eval" || command === "source" || command === ".")) {
      if (command === "eval") return this.analyzeCommand(args.join(" "), cwd, shellEnvironment);
      const script = args.find((arg) => !arg.startsWith("-"));
      return script
        ? this.analyzePathAccess(script, "execute", cwd, command)
        : this.result("ask", [`${command} requires an execution target`]);
    }

    const positional = args.filter((arg) => !arg.startsWith("-") && !unresolvedPathArguments.has(arg));
    const pathArguments = positional.filter((arg) => unmatchedGlobArguments.has(arg) || looksLikePath(arg) || pathExists(this.path(arg, cwd)));
    const pathAccess = (arg: string, kind: AccessKind): PathAccess => {
      const unmatched = unmatchedGlobArguments.has(arg);
      const path = this.path(arg, cwd);
      return { path, kind, source: command, literal: unmatched || isLiteralShellPath(arg), existed: unmatched ? false : pathExists(path) };
    };
    if (category === "read") {
      return this.finalize(pathArguments.map((arg) => pathAccess(arg, "read")), [], [], []);
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
      return this.finalize(pathArguments.map((arg) => pathAccess(arg, "edit")), [], [], []);
    }
    if (category === "delete") {
      const accesses = pathArguments.map((arg): PathAccess => pathAccess(arg, "delete"));
      const trashable = accesses.filter((item) => item.literal).map((item) => item.path);
      return this.finalize(accesses, [], trashable, []);
    }
    // Execute-category tools may run arbitrary nested programs or build logic.
    const accesses = pathArguments.map((arg): PathAccess => pathAccess(arg, "execute"));
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
      if (this.policy.isPolicyPath(path) || this.policy.isSystemReadonlyPath(path) || containsGitMetadata(path)) {
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
      if (this.policy.isSystemReadonlyPath(access.path)) {
        if (["read", "execute"].includes(access.kind)) continue;
        decision = "deny";
        reasons.push(`System read-only path cannot be modified: ${access.path}`);
        continue;
      }
      if (containsGitMetadata(access.path) && ["edit", "delete", "unknown"].includes(access.kind) && access.source !== "git") {
        decision = "deny";
        reasons.push(`Direct .git modification is prohibited: ${access.path}`);
        continue;
      }
      if (access.literal && ["read", "edit", "execute", "unknown"].includes(access.kind) && !(access.existed ?? pathExists(access.path))) continue;
      const ownership = this.policy.ownership(access.path);
      const canEdit = ownership === "edit" || ownership === "full";
      const canExecute = ownership === "execute" || ownership === "full";
      if (access.kind === "execute" && !canExecute) {
        decision = strongest(decision, "ask");
        reasons.push(`Execution requires execute ownership or one-time approval: ${access.path}`);
        ownershipCandidates.push({ path: access.path, required: "execute" });
      } else if (access.kind === "delete" && !canEdit) {
        decision = "deny";
        reasons.push(`Permanent deletion without edit ownership is prohibited: ${access.path}`);
      } else if (["edit", "unknown"].includes(access.kind) && !canEdit) {
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
