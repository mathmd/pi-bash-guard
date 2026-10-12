import { createHash } from "node:crypto";
import { globSync, lstatSync, readFileSync, readdirSync, statSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as shellParse, quote as shellQuote, type ParseToken } from "shell-quote";
import type { AccessKind, Analysis, CommandCategory, Decision, PathAccess, PathExpansion } from "./types.ts";
import { strongest } from "./types.ts";
import { catastrophicInvocation, catastrophicTextReason, containsUnquotedForkBomb } from "./catastrophic-screening.ts";
import { informationalInvocation } from "./informational-commands.ts";
import { canonicalPath, containsGitMetadata, isWithin, looksLikePath, pathExists, pathIsDirectory, resolvePath } from "./path-utils.ts";
import { javascriptExecutions } from "./javascript-screening.ts";
import { selectNodeTestFiles } from "./node-test-selection.ts";
import { selectNpmScripts } from "./npm-scripts.ts";
import { pythonOperations } from "./python-screening.ts";
import { juliaOperations } from "./julia-screening.ts";
import { displayHeredocOperators, extractShellHeredocs, heredocHasDynamicExpansion, isHeredocMarker, type ShellHeredoc } from "./shell-heredoc.ts";
import type { SourceScreening } from "./source-operations.ts";
import type { PolicyStore } from "./policy.ts";
import { isYoloControlPath } from "./live-yolo.ts";
import { builtinCommandCategory, SHELL_CLOSING_WORDS, SHELL_HEADER_WORDS, SHELL_PREFIX_WORDS } from "./command-catalog.ts";
import {
  assignmentEffects, copyShellEnvironment, initialShellEnvironment, invalidateShellEffects, knownShellValue,
  LOGICAL_DIRECTORY, OPAQUE_VARIABLE_WRITES, READONLY_VARIABLES, mergeShellEnvironments, parseShell,
  shellDirectoryChange, shellParameterNames, shellValue, UNKNOWN_CWD, type ShellEnvironment,
} from "./shell-context.ts";

type OpToken = { op: string };
type GlobToken = { op: "glob"; pattern: string };
const CONTROL_OPS = new Set(["|", "|&", "&&", "||", ";", "&", "(", ")"]);
const SOURCE_DYNAMIC_ARGUMENT_PREFIX = "__bash_guard_dynamic_data_";
const REDIRECT_OPS = new Set([">", ">>", "1>", "1>>", "2>", "2>>", "&>", "&>>", ">&", "<&", "<<<", "<"]);
const INTERPRETERS = new Set(["bash", "sh", "zsh", "fish", "python", "python3", "node", "julia", "ruby", "perl", "lua", "luajit", "deno", "bun"]);
const SHELL_INTERPRETERS = new Set(["bash", "sh", "zsh", "fish"]);
type ScriptLanguage = "shell" | "javascript" | "python" | "julia" | "other";
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

const GIT_CLONE_VALUE_OPTIONS = new Set([
  "-b", "--branch", "-o", "--origin", "-u", "--upload-pack", "--depth", "--shallow-since",
  "--shallow-exclude", "--reference", "--reference-if-able", "--separate-git-dir", "-j", "--jobs",
  "--server-option", "--filter", "-c", "--config",
]);

function gitCloneArguments(args: string[]): { repository: string; destination?: string } | undefined {
  const positional: string[] = [];
  for (let index = 0; index < args.length; index++) {
    const arg = args[index]!;
    if (arg === "--") { positional.push(...args.slice(index + 1)); break; }
    if (GIT_CLONE_VALUE_OPTIONS.has(arg)) { index++; continue; }
    if (arg.startsWith("-")) continue;
    positional.push(arg);
  }
  return positional[0] ? { repository: positional[0], ...(positional[1] ? { destination: positional[1] } : {}) } : undefined;
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
function sedInPlaceTargets(args: string[]): string[] {
  const targets: string[] = [];
  let hasProgram = false;
  for (let index = 0; index < args.length; index++) {
    const argument = args[index]!;
    if (["-e", "--expression", "-f", "--file"].includes(argument)) { hasProgram = true; index++; continue; }
    if (/^(?:-e|-f).+/.test(argument) || argument.startsWith("--expression=") || argument.startsWith("--file=")) { hasProgram = true; continue; }
    if (argument === "-i" || argument === "--in-place" || argument.startsWith("-i") || argument.startsWith("--in-place=")) continue;
    if (argument.startsWith("-")) continue;
    if (!hasProgram) { hasProgram = true; continue; }
    targets.push(argument);
  }
  return targets;
}



const XARGS_VALUE_OPTIONS = new Set([
  "-a", "--arg-file", "-d", "--delimiter", "-E", "--eof", "-I", "--replace",
  "-L", "--max-lines", "-n", "--max-args", "-P", "--max-procs", "-s", "--max-chars",
  "--process-slot-var",
]);

function xargsNestedCommand(args: string[]): string[] | undefined {
  for (let index = 0; index < args.length; index++) {
    const arg = args[index]!;
    if (arg === "--") return args.slice(index + 1);
    if (XARGS_VALUE_OPTIONS.has(arg)) { index++; continue; }
    if (arg.startsWith("--") && arg.includes("=")) continue;
    if (/^-[dEILnPs].+/.test(arg) || arg.startsWith("-")) continue;
    return args.slice(index);
  }
  return undefined;
}

function isOp(token: ParseToken): token is OpToken {
  return typeof token === "object" && token !== null && "op" in token;
}

function isGlob(token: ParseToken): token is GlobToken {
  return typeof token === "object" && token !== null && "op" in token && token.op === "glob" && "pattern" in token;
}

function commandName(value: string): string {
  return basename(value);
}


function isLiteralShellPath(value: string): boolean {
  return !/\$(?:[$?!#*@0-9-]|\(|\{|[A-Za-z_])|`/.test(value);
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
  resolvedBindings?: Array<{ name: string; value: string; symbolic?: string }>;
}

interface ShellCommandEntry {
  command: string;
  separatorAfter?: string;
}

function splitShellCommandEntries(command: string): ShellCommandEntry[] {
  const entries: ShellCommandEntry[] = [];
  let start = 0;
  let quote: "'" | '"' | "`" | undefined;
  let escaped = false;
  let parentheses = 0;
  let comment = false;

  const push = (end: number, separatorAfter?: string) => {
    const value = command.slice(start, end).trim();
    if (value) entries.push({ command: value, ...(separatorAfter ? { separatorAfter } : {}) });
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
    const separator = ["&&", "||", "|&", ";;"].includes(two) ? two : [";", "|", "&", "\n"].includes(char) ? char : undefined;
    if (!separator) continue;
    push(index, separator);
    index += separator.length - 1;
    start = index + 1;
  }
  push(command.length);
  return entries.length ? entries : [command.trim()].filter(Boolean).map((value) => ({ command: value }));
}

/** Split top-level shell commands in lexical execution order without changing their source text. */
export function splitShellCommandUnits(command: string): string[] {
  return splitShellCommandEntries(command).map((entry) => entry.command);
}

interface GeneratedPathBinding {
  path: string;
  directory: boolean;
  description: string;
  owned: boolean;
  discoveryPattern?: string;
}
type GeneratedPathEnvironment = Map<string, GeneratedPathBinding>;


const MAX_GLOB_MATCHES = 512;

interface ShellGlobExpansion {
  argument: string;
  matches: string[];
  unresolved: boolean;
  truncated: boolean;
}

// Shell parsing already handled active tilde expansion; source string paths are literal too.
function literalPath(value: string, cwd: string): string {
  return isAbsolute(value) ? value : `${cwd}/${value}`;
}

function expandShellGlob(pattern: string, cwd: string): ShellGlobExpansion {
  const argument = pattern;
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

function staticLoopBinding(command: string, environment: ShellEnvironment, cwd: string): StaticLoopBinding | undefined {
  let tokens: ParseToken[];
  try {
    tokens = parseShell(command.replace(/\\\r?\n/g, " "), environment);
  } catch {
    return undefined;
  }
  const words: string[] = [];
  for (const token of tokens) {
    if (typeof token === "string") words.push(token);
    else if (isGlob(token)) {
      const expansion = expandShellGlob(token.pattern, cwd);
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
    const resolved = literalPath(value, cwd);
    return looksLikePath(value) || pathExists(resolved) ? canonicalPath(resolved) : value;
  });
  return { name: words[start + 1]!, values: [...new Set(concreteValues)] };
}

function referencedShellVariables(command: string): string[] {
  return shellParameterNames(command);
}

function isStaticallyResolvedValue(value: string): boolean {
  return knownShellValue(value);
}

interface MaskedCommandSubstitutions {
  command: string;
  sources: string[];
  arithmetic: boolean;
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
  let hasArithmetic = false;
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
        hasArithmetic = true;
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
  return { command, sources, arithmetic: hasArithmetic };
}

function generatedPathAssignment(
  command: string,
  cwd: string,
  environment: ShellEnvironment,
): { name: string; binding: GeneratedPathBinding } | undefined {
  const masked = maskCommandSubstitutions(command);
  if (masked.sources.length !== 1) return undefined;
  let outerTokens: ParseToken[];
  try { outerTokens = parseShell(masked.command, environment); }
  catch { return undefined; }
  if (!outerTokens.every((token): token is string => typeof token === "string")) return undefined;
  const assignments = ["export", "readonly", "declare", "typeset"].includes(outerTokens[0] ?? "")
    ? outerTokens.slice(1) : outerTokens;
  if (assignments.length !== 1) return undefined;
  const assignment = assignments[0]!.match(/^([A-Za-z_][A-Za-z0-9_]*)=(__bash_guard_substitution_1__)$/);
  if (!assignment) return undefined;

  let tokens: ParseToken[];
  try { tokens = parseShell(masked.sources[0]!, environment); }
  catch { return undefined; }
  if (!tokens.every((token): token is string => typeof token === "string") || commandName(tokens[0] ?? "") !== "mktemp") return undefined;
  const args = tokens.slice(1);
  if (args.some((arg) => arg === "-u" || arg === "--dry-run")) return undefined;
  const directory = args.some((arg) => arg === "-d" || arg === "--directory" || /^-[^-]*d/.test(arg));
  let explicitTmpDir: string | undefined;
  let template: string | undefined;
  let suffix = "";
  let useTmpDir = false;
  for (let index = 0; index < args.length; index++) {
    const arg = args[index]!;
    if (arg === "--") { template = args[index + 1]; break; }
    if (arg === "-p" || arg === "--tmpdir") { explicitTmpDir = args[++index]; useTmpDir = true; continue; }
    if (arg.startsWith("--tmpdir=")) { explicitTmpDir = arg.slice("--tmpdir=".length); useTmpDir = true; continue; }
    if (arg === "-t") { useTmpDir = true; continue; }
    if (arg === "--suffix") { suffix = args[++index] ?? ""; continue; }
    if (arg.startsWith("--suffix=")) { suffix = arg.slice("--suffix=".length); continue; }
    if (arg.startsWith("-")) continue;
    template = arg;
  }
  if (!template) useTmpDir = true;
  const tmpBase = explicitTmpDir || environment.TMPDIR || "/tmp";
  if (!knownShellValue(tmpBase) || (template !== undefined && !knownShellValue(template)) || !knownShellValue(suffix)) return undefined;
  const base = explicitTmpDir || useTmpDir
    ? literalPath(tmpBase, cwd)
    : template?.includes("/") ? dirname(literalPath(template, cwd)) : cwd;
  const canonicalBase = canonicalPath(base);
  const name = assignment[1]!;
  const digest = createHash("sha256").update(`${command}\0${cwd}\0${name}`).digest("hex").slice(0, 12);
  const path = join(canonicalBase, `.bash-guard-mktemp-${name}-${digest}`);
  const templateName = basename(template ?? "tmp.XXXXXXXXXX");
  const wildcardName = templateName.replace(/X{3,}/g, "*");
  const discoveryPattern = wildcardName === templateName ? undefined : join(canonicalBase, `${wildcardName}${suffix}`);
  return {
    name,
    binding: {
      path,
      directory,
      owned: true,
      ...(discoveryPattern ? { discoveryPattern } : {}),
      description: `runtime ${directory ? "directory" : "file"} created by mktemp under ${canonicalBase}`,
    },
  };
}

function specialParameterPathBinding(
  name: string,
  value: string,
  cwd: string,
): GeneratedPathBinding | undefined {
  if (!value.includes("$$") || /[*?\[]/.test(value) || (!looksLikePath(value) && !value.includes("/"))) return undefined;
  if (!knownShellValue(value.replaceAll("$$", "shell-pid"))) return undefined;
  const resolved = literalPath(value, cwd);
  const digest = createHash("sha256").update(`${name}\0${value}\0${cwd}`).digest("hex").slice(0, 12);
  const marker = `.bash-guard-shell-pid-${digest}`;
  return {
    path: canonicalPath(resolved.replace(/\$\$/g, marker)),
    directory: false,
    owned: false,
    description: `runtime path ${resolved.replace(/\$\$/g, "<shell-pid>")}`,
    discoveryPattern: resolved.replace(/\$\$/g, "[0-9]*"),
  };
}

interface InlineSourceArgument {
  argumentIndex: number;
  source?: string;
  language: ScriptLanguage;
  opaque: boolean;
}

const NODE_OPTION_VALUES = new Set([
  "--conditions", "--diagnostic-dir", "--experimental-loader", "--input-type", "--import", "--loader",
  "--redirect-warnings", "--require", "-C", "-r",
]);
const PYTHON_OPTION_VALUES = new Set(["-W", "-X"]);
const JULIA_OPTION_VALUES = new Set([
  "--bug-report", "--check-bounds", "--code-coverage", "--color", "--compiled-modules", "--cpu-target",
  "--depwarn", "--gcthreads", "--handle-signals", "--heap-size-hint", "--history-file", "--home",
  "--image-codegen", "--inline", "--machine-file", "--math-mode", "--optimize", "--output-bc",
  "--output-code-coverage", "--output-incremental", "--output-ji", "--output-o", "--output-unopt-bc",
  "--pkgimages", "--procs", "--startup-file", "--sysimage", "--threads", "--track-allocation",
  "--warn-overwrite", "--warn-scope", "-g", "-H", "-J", "-O", "-p", "-t",
]);

function optionHasInlineValue(argument: string, options: Set<string>): boolean {
  return [...options].some((option) => option.startsWith("--") && argument.startsWith(`${option}=`));
}

function inlineSourceArguments(command: string, args: string[]): InlineSourceArgument[] {
  const found: InlineSourceArgument[] = [];
  const separate = (index: number, language: ScriptLanguage, opaque: boolean): number => {
    found.push({ argumentIndex: index + 1, source: args[index + 1], language, opaque });
    return index + 1;
  };
  const attached = (index: number, source: string, language: ScriptLanguage, opaque: boolean): void => {
    found.push({ argumentIndex: index, source, language, opaque });
  };

  if (command === "node") {
    for (let index = 0; index < args.length; index++) {
      const argument = args[index]!;
      if (argument === "--") break;
      if (["-e", "--eval", "-p", "--print"].includes(argument) || /^-[ep]+$/.test(argument)) { separate(index, "javascript", false); break; }
      const long = argument.match(/^--(?:eval|print)=(.*)$/s);
      if (long) { attached(index, long[1]!, "javascript", false); break; }
      const short = argument.match(/^-[ep](.+)$/s);
      if (short) { attached(index, short[1]!, "javascript", false); break; }
      if (NODE_OPTION_VALUES.has(argument)) { index++; continue; }
      if (optionHasInlineValue(argument, NODE_OPTION_VALUES)) continue;
      if (!argument.startsWith("-")) break;
    }
    return found;
  }

  if (["python", "python3"].includes(command)) {
    for (let index = 0; index < args.length; index++) {
      const argument = args[index]!;
      if (argument === "--" || argument === "-m" || /^-m.+/.test(argument)) break;
      if (argument === "-c") { separate(index, "python", false); break; }
      if (argument.startsWith("-c") && argument.length > 2) { attached(index, argument.slice(2), "python", false); break; }
      if (PYTHON_OPTION_VALUES.has(argument)) { index++; continue; }
      if (!argument.startsWith("-")) break;
    }
    return found;
  }

  if (command === "julia") {
    for (let index = 0; index < args.length; index++) {
      const argument = args[index]!;
      if (argument === "--") break;
      if (["-e", "--eval", "-E", "--print"].includes(argument)) { index = separate(index, "julia", false); continue; }
      const long = argument.match(/^--(?:eval|print)=(.*)$/s);
      if (long) { attached(index, long[1]!, "julia", false); continue; }
      const short = argument.match(/^-[eE](.+)$/s);
      if (short) { attached(index, short[1]!, "julia", false); continue; }
      if (["-L", "--load", "-m", "--module"].includes(argument) || JULIA_OPTION_VALUES.has(argument)) { index++; continue; }
      if (/^-(?:L|m).+/.test(argument) || /^--(?:load|module)=/.test(argument) || optionHasInlineValue(argument, JULIA_OPTION_VALUES)) continue;
      if (!argument.startsWith("-")) break;
    }
    return found;
  }

  if (SHELL_INTERPRETERS.has(command)) {
    for (let index = 0; index < args.length; index++) {
      const argument = args[index]!;
      if (argument === "--") break;
      if (argument === "-c" || /^-[^-]*c/.test(argument)) { separate(index, "shell", false); break; }
      if (["--rcfile", "--init-file", "-O", "+O"].includes(argument)) index++;
      else if (!argument.startsWith("-") && !argument.startsWith("+")) break;
    }
    return found;
  }

  const opaqueFlags: Record<string, Set<string>> = {
    ruby: new Set(["-e"]),
    perl: new Set(["-e", "-E"]),
    lua: new Set(["-e"]),
    luajit: new Set(["-e"]),
    bun: new Set(["-e", "--eval", "-p", "--print"]),
  };
  const flags = opaqueFlags[command];
  for (let index = 0; index < args.length; index++) {
    const argument = args[index]!;
    if (argument === "--") break;
    if ((command === "deno" || command === "bun") && argument === "eval") { separate(index, "other", true); break; }
    if (flags?.has(argument)) { index = separate(index, "other", true); continue; }
    const long = [...(flags ?? [])].find((flag) => flag.startsWith("--") && argument.startsWith(`${flag}=`));
    if (long) { attached(index, argument.slice(long.length + 1), "other", true); continue; }
    const short = [...(flags ?? [])].find((flag) => !flag.startsWith("--") && argument.startsWith(flag) && argument.length > flag.length);
    if (short) { attached(index, argument.slice(short.length), "other", true); continue; }
    if (!argument.startsWith("-")) break;
  }
  return found;
}

function hasOpaqueInlineCode(command: string, args: string[]): boolean {
  return inlineSourceArguments(command, args).some((source) => source.opaque);
}

function interpreterReadsStdin(command: string, args: string[]): boolean {
  if (command === "node") {
    if (args.some((argument) => argument === "--test" || argument.startsWith("--test="))) return false;
    const valueOptions = new Set(["--input-type", "--conditions", "--experimental-loader", "--import", "--loader", "--require", "-C", "-r"]);
    for (let index = 0; index < args.length; index++) {
      const argument = args[index]!;
      if (argument === "--") return args[index + 1] === "-" || args[index + 1] === undefined;
      if (valueOptions.has(argument)) { index++; continue; }
      if ([...valueOptions].some((option) => option.startsWith("--") && argument.startsWith(`${option}=`))) continue;
      if (argument === "-") return true;
      if (!argument.startsWith("-")) return false;
    }
    return true;
  }
  if (["python", "python3"].includes(command)) {
    const valueOptions = new Set(["-W", "-X"]);
    for (let index = 0; index < args.length; index++) {
      const argument = args[index]!;
      if (["-c", "-m"].includes(argument) || /^-[cm].+/.test(argument)) return false;
      if (argument === "--") return args[index + 1] === "-" || args[index + 1] === undefined;
      if (valueOptions.has(argument)) { index++; continue; }
      if (argument === "-") return true;
      if (!argument.startsWith("-")) return false;
    }
    return true;
  }
  if (command === "julia") {
    if (inlineSourceArguments(command, args).length || juliaModuleArgument(args) || juliaScriptArgument(args)) return false;
    return true;
  }
  if (SHELL_INTERPRETERS.has(command)) {
    if (args.some((argument) => argument === "-c" || /^-[^-]*c/.test(argument))) return false;
    return !args.some((argument) => !argument.startsWith("-") && argument !== "-") || args.includes("-s") || args.includes("-");
  }
  return false;
}

function interpreterScriptArgument(command: string, args: string[]): string | undefined {
  const valueOptions = command === "node"
    ? new Set(["--conditions", "--diagnostic-dir", "--experimental-loader", "--input-type", "--import", "--loader", "--redirect-warnings", "--require", "-C", "-r"])
    : ["python", "python3"].includes(command) ? new Set(["-W", "-X"]) : new Set<string>();
  for (let index = 0; index < args.length; index++) {
    const argument = args[index]!;
    if (argument === "--") return args[index + 1] === "-" ? undefined : args[index + 1];
    if (valueOptions.has(argument)) { index++; continue; }
    if ([...valueOptions].some((option) => option.startsWith("--") && argument.startsWith(`${option}=`))) continue;
    if (argument === "-") return undefined;
    if (!argument.startsWith("-")) return argument;
  }
  return undefined;
}

interface NodePreload { value?: string; source: string; }

function nodePreloads(args: string[]): NodePreload[] {
  const options = new Map([
    ["-r", "node --require"], ["--require", "node --require"],
    ["--import", "node --import"], ["--loader", "node --loader"], ["--experimental-loader", "node --experimental-loader"],
  ]);
  const preloads: NodePreload[] = [];
  for (let index = 0; index < args.length; index++) {
    const argument = args[index]!;
    const source = options.get(argument);
    if (source) { preloads.push({ value: args[++index], source }); continue; }
    for (const [option, label] of options) {
      if (option.startsWith("--") && argument.startsWith(`${option}=`)) {
        preloads.push({ value: argument.slice(option.length + 1), source: label });
        break;
      }
    }
  }
  return preloads;
}

interface JuliaPreload { value?: string; source: string; }

function juliaPreloads(args: string[]): JuliaPreload[] {
  const preloads: JuliaPreload[] = [];
  for (let index = 0; index < args.length; index++) {
    const argument = args[index]!;
    if (argument === "-L" || argument === "--load") {
      preloads.push({ value: args[++index], source: "julia --load" });
      continue;
    }
    const long = argument.match(/^--load=(.*)$/s);
    if (long) { preloads.push({ value: long[1], source: "julia --load" }); continue; }
    const short = argument.match(/^-L(.+)$/s);
    if (short) preloads.push({ value: short[1], source: "julia --load" });
  }
  return preloads;
}

function juliaModuleArgument(args: string[]): string | undefined {
  for (let index = 0; index < args.length; index++) {
    const argument = args[index]!;
    if (argument === "-m" || argument === "--module") return args[index + 1];
    const attached = argument.match(/^(?:-m|--module=)(.+)$/s);
    if (attached) return attached[1];
  }
  return undefined;
}

function juliaScriptArgument(args: string[]): string | undefined {
  for (let index = 0; index < args.length; index++) {
    const argument = args[index]!;
    if (argument === "--") return args[index + 1] === "-" ? undefined : args[index + 1];
    if (["-e", "--eval", "-E", "--print", "-L", "--load", "-m", "--module"].includes(argument) || JULIA_OPTION_VALUES.has(argument)) { index++; continue; }
    if (/^-[eELm].+/.test(argument) || /^--(?:eval|print|load|module)=/.test(argument) || optionHasInlineValue(argument, JULIA_OPTION_VALUES)) continue;
    if (argument === "-") return undefined;
    if (!argument.startsWith("-")) return argument;
  }
  return undefined;
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
type AnalysisContext = "direct" | "source";
type SourceInspectionRole = "entry" | "module";

function scriptLanguage(path: string, interpreter: string | undefined, source: string): ScriptLanguage {
  if (interpreter && SHELL_INTERPRETERS.has(interpreter)) return "shell";
  if (interpreter && ["node", "deno", "bun"].includes(interpreter)) return "javascript";
  if (interpreter && ["python", "python3"].includes(interpreter)) return "python";
  if (interpreter === "julia") return "julia";
  if (/\.(?:[cm]?[jt]s)$/i.test(path)) return "javascript";
  if (/\.py(?:w)?$/i.test(path)) return "python";
  if (/\.jl$/i.test(path)) return "julia";
  const shebang = source.split("\n", 1)[0] ?? "";
  if (/^#!.*\b(?:ba|z|fi)?sh\b/.test(shebang)) return "shell";
  if (/^#!.*\b(?:node|deno|bun)\b/.test(shebang)) return "javascript";
  if (/^#!.*\bpython(?:3(?:\.\d+)?)?\b/.test(shebang)) return "python";
  if (/^#!.*\bjulia\b/.test(shebang)) return "julia";
  return "other";
}

function combineAnalyses(items: Analysis[]): Analysis {
  return items.reduce<Analysis>((result, item) => ({
    decision: strongest(result.decision, item.decision),
    reasons: [...new Set([...result.reasons, ...item.reasons])],
    accesses: [...result.accesses, ...item.accesses],
    creationCandidates: [...new Set([...result.creationCandidates, ...item.creationCandidates])],
    // Nested script deletion cannot safely be rewritten as a standalone trash command.
    trashablePaths: [],
    ownershipCandidates: [...result.ownershipCandidates, ...item.ownershipCandidates].filter((candidate, index, all) =>
      all.findIndex((other) => other.path === candidate.path && other.required === candidate.required) === index),
    unknownCommands: [...(result.unknownCommands ?? []), ...(item.unknownCommands ?? [])],
    pathExpansions: [...(result.pathExpansions ?? []), ...(item.pathExpansions ?? [])],
    creationPatterns: [...new Set([...(result.creationPatterns ?? []), ...(item.creationPatterns ?? [])])],
  }), { decision: "allow", reasons: [], accesses: [], creationCandidates: [], trashablePaths: [], ownershipCandidates: [] });
}

export class GuardAnalyzer {
  private readonly policy: PolicyStore;
  private readonly screeningPaths = new Set<string>();
  private readonly npmScriptStack = new Set<string>();
  private shellDepth = 0;
  private remainingShellUnits = 1024;

  constructor(policy: PolicyStore) {
    this.policy = policy;
  }

  private path(raw: string, cwd: string): string {
    if (cwd === UNKNOWN_CWD && !isAbsolute(raw)) {
      return `${UNKNOWN_CWD}/${raw.replace(/(^|\/)\.\.(?=\/|$)/g, "$1__parent__")}`;
    }
    return canonicalPath(literalPath(raw, cwd));
  }

  private modulePath(raw: string, base: string, language: "javascript" | "python" | "julia" = "javascript"): string {
    let candidate: string;
    try { candidate = raw.startsWith("file:") ? canonicalPath(fileURLToPath(raw)) : this.path(raw, base); }
    catch { return this.path(raw, base); }
    if (pathExists(candidate) && !pathIsDirectory(candidate)) return candidate;
    const suffixes = language === "python" ? [".py"] : language === "julia" ? [".jl"] : [".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".json"];
    for (const suffix of suffixes) {
      if (pathExists(`${candidate}${suffix}`)) return canonicalPath(`${candidate}${suffix}`);
    }
    const names = language === "python"
      ? ["__init__.py"]
      : language === "julia"
        ? [`${basename(candidate)}.jl`, join("src", `${basename(candidate)}.jl`)]
        : ["index.js", "index.mjs", "index.cjs", "index.ts", "index.mts", "index.cts", "index.json"];
    for (const name of names) {
      const nested = join(candidate, name);
      if (pathExists(nested)) return canonicalPath(nested);
    }
    if (language === "julia" && /^[A-Za-z_]\w*$/.test(raw)) {
      const projectModule = join(base, "src", `${raw}.jl`);
      if (pathExists(projectModule)) return canonicalPath(projectModule);
    }
    return candidate;
  }
  private isInspectableSource(path: string, projectRoot: string, role: SourceInspectionRole): boolean {
    const canonical = canonicalPath(path);
    if (this.policy.isSystemReadonlyPath(canonical)) return false;
    if (/(?:^|[\\/])(?:node_modules|\.julia[\\/](?:artifacts|compiled|environments|packages|registries|scratchspaces))[\\/]/.test(canonical)) return false;
    return role === "entry" || isWithin(canonical, canonicalPath(projectRoot));
  }

  private executableVariableNames(
    command: string,
    cwd: string,
    environment: ShellEnvironment,
    generatedPaths: GeneratedPathEnvironment,
    heredocs: Map<string, ShellHeredoc>,
  ): string[] {
    const executableNames: string[] = [];
    for (const name of referencedShellVariables(command)) {
      const marker = `__bash_guard_variable_${name}__`;
      const probe = this.analyzeCommand(command, cwd, { ...environment, [name]: marker }, generatedPaths, heredocs);
      const isCommand = probe.reasons.some((reason) => reason.startsWith("Unknown command ") && reason.includes(marker));
      const isExecutionTarget = probe.accesses.some((access) => access.kind === "execute" &&
        (access.source?.includes(marker) || access.path.includes(marker)));
      if (isCommand || isExecutionTarget) executableNames.push(name);
    }
    return executableNames;
  }

  analyzeCommandUnits(
    command: string,
    cwd: string,
    analysisContext: AnalysisContext = "direct",
    sourceRoot = cwd,
    initialEnvironment: ShellEnvironment = {},
    initialGeneratedPaths: GeneratedPathEnvironment = new Map(),
  ): CommandAnalysisUnit[] {
    if (this.shellDepth === 0) this.remainingShellUnits = 1024;
    if (this.shellDepth >= 32 || this.remainingShellUnits <= 0) {
      return [{ command, analysis: this.result("ask", ["Shell context analysis exceeds its nested inspection limit"]) }];
    }
    this.shellDepth++;
    try { return this.analyzeShellUnits(command, cwd, analysisContext, sourceRoot, initialEnvironment, initialGeneratedPaths); }
    finally { this.shellDepth--; }
  }

  private analyzeShellUnits(
    command: string,
    cwd: string,
    analysisContext: AnalysisContext,
    sourceRoot: string,
    initialEnvironment: ShellEnvironment,
    initialGeneratedPaths: GeneratedPathEnvironment,
  ): CommandAnalysisUnit[] {
    const extracted = extractShellHeredocs(command);
    if (extracted.error) return [{ command, analysis: this.result("ask", [extracted.error]) }];
    command = extracted.command;
    let environment = initialShellEnvironment(cwd, this.policy.home, initialEnvironment);
    let candidates = new Map<string, string[]>();
    let generatedPaths: GeneratedPathEnvironment = new Map([...initialGeneratedPaths].map(([name, binding]) => [name, { ...binding }]));
    let readonlyNames = new Set(initialEnvironment[READONLY_VARIABLES]);
    let workingDirectory = cwd === UNKNOWN_CWD ? cwd : canonicalPath(cwd);
    const loops: Array<{ name: string; values?: string[]; previous?: string[] }> = [];
    const results: CommandAnalysisUnit[] = [];
    const snapshot = () => ({ environment: copyShellEnvironment(environment), cwd: workingDirectory, candidates: new Map(candidates),
      generated: new Map([...generatedPaths].map(([name, binding]) => [name, { ...binding }])), readonly: new Set(readonlyNames) });
    type State = ReturnType<typeof snapshot>;
    const restore = (state: State) => {
      environment = copyShellEnvironment(state.environment); workingDirectory = state.cwd; candidates = new Map(state.candidates);
      generatedPaths = new Map([...state.generated].map(([name, binding]) => [name, { ...binding }])); readonlyNames = new Set(state.readonly);
    };
    const merge = (states: State[]) => {
      const merged = mergeShellEnvironments(states.map((state) => state.environment));
      workingDirectory = states.every((state) => state.cwd === states[0]!.cwd) ? states[0]!.cwd : UNKNOWN_CWD;
      candidates = new Map();
      for (const name of Object.keys(merged)) {
        const values = [...new Set(states.flatMap((state) => state.candidates.get(name) ?? [shellValue(state.environment, name) ?? `$${name}`]))];
        if (values.length > 1 && values.length <= 128) candidates.set(name, values);
      }
      generatedPaths = new Map([...states[0]!.generated].filter(([name, binding]) => states.every((state) => state.generated.get(name)?.path === binding.path && state.generated.get(name)?.owned === binding.owned)));
      readonlyNames = new Set(states.flatMap((state) => [...state.readonly]));
      for (const name of readonlyNames) if (!states.every((state) => state.readonly.has(name))) merged[name] = `$${name}`;
      environment = merged;
    };
    const branches: Array<{ before: State; ends: State[]; hasElse: boolean }> = [];
    let conditional: State | undefined;
    let pipeline: State | undefined;
    let previousSeparator: string | undefined;
    let groupStart = snapshot();
    const entries = splitShellCommandEntries(command);
    for (const entry of entries) {
      if (results.length >= 1024 || this.remainingShellUnits-- <= 0) {
        results.push({ command: entry.command, analysis: this.result("ask", ["Shell context analysis exceeds 1024 command units"]) });
        break;
      }
      const unit = entry.command;
      const masked = maskCommandSubstitutions(unit);
      const displayUnit = displayHeredocOperators(unit, extracted.heredocs);
      if (!previousSeparator || !["&&", "||", "|", "|&"].includes(previousSeparator)) groupStart = snapshot();
      if (["|", "|&"].includes(entry.separatorAfter ?? "") && !pipeline) pipeline = snapshot();
      if (pipeline) restore(pipeline);
      if (/^(?:else|elif)\b/.test(unit.trim()) && branches.length) {
        const branch = branches.at(-1)!; branch.ends.push(snapshot()); restore(branch.before);
        branch.hasElse ||= /^else\b/.test(unit.trim());
      }
      if (/^if\b/.test(unit.trim())) branches.push({ before: snapshot(), ends: [], hasElse: false });
      if (/^(?:while|until|case)\b/.test(unit.trim())) {
        for (const name of Object.keys(environment)) environment[name] = `$${name}`;
        candidates.clear(); generatedPaths.clear(); workingDirectory = UNKNOWN_CWD;
      }
      if (previousSeparator === "||" && conditional) merge([conditional, snapshot()]);
      if (masked.arithmetic) {
        for (const name of Object.keys(environment)) if (!readonlyNames.has(name)) environment[name] = `$${name}`;
        candidates.clear(); generatedPaths.clear();
      }
      environment[READONLY_VARIABLES] = new Set(readonlyNames);
      const unitCwd = workingDirectory;
      const resultStart = results.length;
      const generated = environment[OPAQUE_VARIABLE_WRITES] ? undefined : generatedPathAssignment(unit, unitCwd, environment);
      const generatedWritable = generated && !readonlyNames.has(generated.name);
      const loop = staticLoopBinding(unit, environment, unitCwd);
      const loopName = unit.trim().match(/^(?:(?:then|do)\s+)?for\s+([A-Za-z_][A-Za-z0-9_]*)\b/)?.[1];
      if (loopName) {
        results.push({ command: displayUnit, analysis: this.analyzeCommand(unit, unitCwd, environment, generatedPaths, extracted.heredocs, analysisContext, sourceRoot) });
        loops.push({ name: loopName, values: loop?.values, previous: candidates.get(loopName) });
        if (loop) candidates.set(loopName, loop.values);
        else { candidates.delete(loopName); environment[loopName] = `$${loopName}`; }
        previousSeparator = entry.separatorAfter;
        continue;
      }
      const referencedNames = referencedShellVariables(unit);
      const executableNames = this.executableVariableNames(unit, unitCwd, environment, generatedPaths, extracted.heredocs);
      const expansionNames = [...new Set([...executableNames, ...referencedNames.filter((name) => candidates.has(name))])];
      let contexts: Array<{ environment: ShellEnvironment; bindings: Array<{ name: string; value?: string }> }> = [
        { environment: { ...environment }, bindings: [] },
      ];
      let expansionLimited = false;
      for (const name of expansionNames) {
        const values = (candidates.get(name) ?? [shellValue(environment, name)]).map((value) => knownShellValue(value) ? value : undefined);
        if (contexts.length * values.length > 128) {
          expansionLimited = true;
          const unresolvedEnvironment = { ...environment };
          for (const variable of expansionNames) unresolvedEnvironment[variable] = `$${variable}`;
          contexts = [{ environment: unresolvedEnvironment, bindings: expansionNames.map((variable) => ({ name: variable })) }];
          break;
        }
        contexts = contexts.flatMap((context) => values.map((value) => ({
          environment: { ...context.environment, [name]: value ?? `$${name}` },
          bindings: [...context.bindings, { name, ...(value === undefined ? {} : { value }) }],
        })));
      }
      const updatesByContext: ShellEnvironment[] = [];
      const subshell = unit.trim().startsWith("(") && !unit.trim().startsWith("((") && closingParenthesis(unit.trim(), 1) === unit.trim().length - 1;
      for (const context of contexts) {
        const analysis = subshell
          ? combineAnalyses(this.analyzeCommandUnits(unit.trim().slice(1, -1), unitCwd, analysisContext, sourceRoot, context.environment, generatedPaths).map((item) => item.analysis))
          : this.analyzeCommand(unit, unitCwd, context.environment, generatedPaths, extracted.heredocs, analysisContext, sourceRoot);
        if (generated) {
          const safety = this.finalize([], [generated.binding.path], [], [], generatedPaths);
          analysis.decision = strongest(analysis.decision, safety.decision);
          analysis.reasons.push(...safety.reasons);
          analysis.accesses.push(...safety.accesses);
          analysis.ownershipCandidates.push(...safety.ownershipCandidates);
          if (generated.binding.discoveryPattern && !generated.binding.discoveryPattern.startsWith(UNKNOWN_CWD)) analysis.creationPatterns = [...(analysis.creationPatterns ?? []), generated.binding.discoveryPattern];
        }
        if (expansionLimited) {
          analysis.decision = strongest(analysis.decision, "ask");
          analysis.reasons.push("Static variable expansion has more than 128 candidate combinations and cannot be analyzed safely");
        }
        const resolvedBindings = referencedNames.flatMap((name) => {
          const value = shellValue(context.environment, name);
          const symbolic = generatedPaths.get(name)?.description;
          return value !== undefined ? [{ name, value, ...(symbolic ? { symbolic } : {}) }] : [];
        });
        results.push({ command: displayUnit, analysis,
          ...(context.bindings.some(({ name }) => executableNames.includes(name)) ? { executableBindings: context.bindings.filter(({ name }) => executableNames.includes(name)) } : {}),
          ...(resolvedBindings.length ? { resolvedBindings } : {}),
        });
        const effects = subshell ? undefined : assignmentEffects(masked.command, context.environment, readonlyNames);
        if (effects) {
          updatesByContext.push(effects.updates);
          for (const name of effects.readonly) readonlyNames.add(name);
        }
      }
      for (const binding of generatedPaths.values()) {
        if (binding.owned) continue;
        if (results.slice(resultStart).some(({ analysis }) => analysis.creationCandidates.includes(binding.path))) {
          binding.owned = true;
          binding.directory = /(?:^|\s)mkdir(?:\s|$)|(?:^|\s)git(?:\s+[^;&|]+)?\s+clone(?:\s|$)/.test(unit);
        }
      }
      if (updatesByContext.length) {
        const updates = mergeShellEnvironments(updatesByContext);
        Object.assign(environment, updates);
        for (const [name, value] of Object.entries(updates)) {
          const values = updatesByContext.map((updates) => updates[name]);
          candidates.delete(name);
          if (values.length > 1) candidates.set(name, [...new Set(values.map((value) => knownShellValue(value) ? value : `$${name}`))]);
          const special = value === undefined ? undefined : specialParameterPathBinding(name, value, unitCwd);
          if (special) { environment[name] = special.path; generatedPaths.set(name, special); }
          else generatedPaths.delete(name);
        }
      }
      if (generated && generatedWritable) {
        environment[generated.name] = generated.binding.path; generatedPaths.set(generated.name, generated.binding); candidates.delete(generated.name);
      }
      if (!subshell) {
        const invalidated = invalidateShellEffects(masked.command, environment, readonlyNames);
        for (const name of invalidated) { candidates.delete(name); generatedPaths.delete(name); }
        if (environment[LOGICAL_DIRECTORY] === UNKNOWN_CWD) workingDirectory = UNKNOWN_CWD;
        const cd = shellDirectoryChange(masked.command, unitCwd, environment, (path) => pathIsDirectory(path) || [...generatedPaths.values()].some((binding) => binding.directory && binding.path === path));
        if (cd) {
          if (!readonlyNames.has("OLDPWD")) environment.OLDPWD = shellValue(environment, "PWD") ?? "$OLDPWD";
          environment[LOGICAL_DIRECTORY] = contexts.length === 1 ? cd.logical : UNKNOWN_CWD;
          if (!readonlyNames.has("PWD")) environment.PWD = contexts.length === 1 ? cd.logical : "$PWD";
          workingDirectory = contexts.length === 1 ? cd.cwd : UNKNOWN_CWD;
        }
      }
      if (/^(?:(?:then|do)\s+)?(?:break|continue)\b/.test(unit.trim()) && loops.length) loops.at(-1)!.values = undefined;
      if (/^done(?:\s|$)/.test(unit.trim())) {
        const closed = loops.pop();
        if (closed) {
          environment[closed.name] = closed.values?.at(-1) ?? `$${closed.name}`;
          if (closed.previous) candidates.set(closed.name, closed.previous); else candidates.delete(closed.name);
        }
      }
      if (/^fi\b/.test(unit.trim()) && branches.length) {
        const branch = branches.pop()!;
        merge([...branch.ends, snapshot(), ...(!branch.hasElse ? [branch.before] : [])]);
      }
      if (pipeline && !["|", "|&"].includes(entry.separatorAfter ?? "")) {
        // Bash lastpipe may run the final builtin in the parent; retain only facts common to both.
        merge([pipeline, snapshot()]); pipeline = undefined;
      }
      if (conditional && !["&&", "||", "|", "|&"].includes(entry.separatorAfter ?? "")) { merge([conditional, snapshot()]); conditional = undefined; }
      if (!conditional && ["&&", "||"].includes(entry.separatorAfter ?? "")) conditional = snapshot();
      if (entry.separatorAfter === "&") { restore(groupStart); conditional = undefined; pipeline = undefined; }
      previousSeparator = entry.separatorAfter;
    }
    return results;
  }

  analyzePathAccess(path: string, kind: AccessKind, cwd: string, source: string, literal = true): Analysis {
    const lexicalPath = resolvePath(path, cwd, this.policy.home);
    if (["read", "edit"].includes(kind) && this.policy.isSafeProcessIoPath(lexicalPath)) return this.result("allow", []);
    return this.finalize([{ path: this.path(lexicalPath, cwd), kind, source, literal }], [], [], []);
  }

  analyzeCommand(
    command: string,
    cwd: string,
    shellEnvironment: ShellEnvironment = {},
    generatedPaths: GeneratedPathEnvironment = new Map(),
    heredocs: Map<string, ShellHeredoc> = new Map(),
    analysisContext: AnalysisContext = "direct",
    sourceRoot = cwd,
  ): Analysis {
    shellEnvironment = initialShellEnvironment(cwd, this.policy.home, shellEnvironment);
    const substitutions = maskCommandSubstitutions(command);
    if (containsUnquotedForkBomb(substitutions.command)) {
      return this.result("deny", ["Catastrophic operation: fork bomb"]);
    }
    let tokens: ParseToken[];
    try {
      const normalizedCommand = substitutions.command.replace(/\\\r?\n/g, " ").replace(/\n/g, " ; ");
      tokens = parseShell(normalizedCommand, shellEnvironment);
    }
    catch { return this.result("ask", ["Shell syntax could not be analyzed safely"]); }

    const accesses: PathAccess[] = [];
    const creations: string[] = [];
    const trashable: string[] = [];
    const reasons: string[] = [];
    const unknownCommands: NonNullable<Analysis["unknownCommands"]> = [];
    let baseDecision: Decision = "allow";
    const unresolvedEvidence = (reason: string): void => {
      if (analysisContext === "source") return;
      baseDecision = strongest(baseDecision, "ask");
      reasons.push(reason);
    };
    if (cwd === UNKNOWN_CWD) unresolvedEvidence("Working directory cannot be resolved statically after a shell state change");
    const pathExpansions: PathExpansion[] = [];
    const unmatchedGlobArguments = new Set<string>();
    const unresolvedPathArguments = new Set<string>();
    const creationPatterns: string[] = [];
    const mergeNested = (nested: Analysis): void => {
      baseDecision = strongest(baseDecision, nested.decision);
      reasons.push(...nested.reasons);
      accesses.push(...nested.accesses);
      creations.push(...nested.creationCandidates);
      trashable.push(...nested.trashablePaths);
      unknownCommands.push(...(nested.unknownCommands ?? []));
      pathExpansions.push(...(nested.pathExpansions ?? []));
      creationPatterns.push(...(nested.creationPatterns ?? []));
    };

    for (const source of substitutions.sources) {
      for (const unit of this.analyzeCommandUnits(source, cwd, analysisContext, sourceRoot, shellEnvironment, generatedPaths)) mergeNested(unit.analysis);
    }
    for (const segment of splitSegments(tokens)) {
      const commandWords: string[] = [];
      for (let i = 0; i < segment.length; i++) {
        const token = segment[i];
        if (isGlob(token)) {
          const expansion = expandShellGlob(token.pattern, cwd);
          pathExpansions.push({
            expression: token.pattern,
            matches: expansion.matches.map((match) => this.path(match, cwd)),
            ...(expansion.unresolved ? { unresolved: true } : {}),
            ...(expansion.truncated ? { truncated: true } : {}),
          });
          if (expansion.unresolved || expansion.truncated) {
            unresolvedPathArguments.add(expansion.argument);
            if (expansion.truncated) {
              baseDecision = strongest(baseDecision, "ask");
              reasons.push(`Wildcard path has more than ${MAX_GLOB_MATCHES} matches and cannot be analyzed completely: ${token.pattern}`);
            } else {
              unresolvedEvidence(`Dynamic path cannot be resolved statically: ${token.pattern}`);
            }
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
            if (token.op !== "<<<" && !descriptorTarget && !isStaticallyResolvedValue(target)) {
              unresolvedEvidence(`Dynamic redirection target cannot be resolved statically: ${target}`);
              i++;
              continue;
            }
            const lexicalPath = literalPath(target, cwd);
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
      const heredocInputs = commandWords.filter((word) => isHeredocMarker(word) && heredocs.has(word)).map((marker) => heredocs.get(marker)!);
      const strings = commandWords.filter((word) => !(isHeredocMarker(word) && heredocs.has(word)));
      if (!strings.length) continue;
      let index = 0;
      while (index < strings.length && /^[A-Za-z_][A-Za-z0-9_]*\+?=/.test(strings[index])) index++;
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
        if (!["env", "command", "builtin", "exec", "nohup"].includes(wrapper)) break;
        index++;
        while (strings[index]?.startsWith("-")) index++;
        while (/^[A-Za-z_][A-Za-z0-9_]*=/.test(strings[index] ?? "")) index++;
      }
      let elevated = false;
      if (commandName(strings[index] ?? "") === "sudo") {
        elevated = true;
        index++;
        while (strings[index]?.startsWith("-")) index++;
      }
      const executableRaw = strings[index];
      if (!executableRaw) continue;
      const cmd = commandName(executableRaw);
      const args = strings.slice(index + 1).filter((arg) => !REDIRECT_OPS.has(arg));
      const inlineSources = inlineSourceArguments(cmd, args);
      const inlineSourceIndexes = new Set(inlineSources.map((source) => source.argumentIndex));
      const invocationArguments = args.filter((_, argumentIndex) => !inlineSourceIndexes.has(argumentIndex));
      const sourceInvocationIncomplete = analysisContext === "source" &&
        (!isStaticallyResolvedValue(executableRaw) || invocationArguments.some((arg) => !isStaticallyResolvedValue(arg)));
      if (elevated && !sourceInvocationIncomplete) {
        baseDecision = strongest(baseDecision, "ask");
        reasons.push("Elevated execution requires approval");
      }
      for (const heredoc of heredocInputs.filter((item) => !item.quotedDelimiter)) {
        const expanded = maskCommandSubstitutions(heredoc.source);
        for (const source of expanded.sources) mergeNested(this.analyzeCommand(source, cwd, shellEnvironment, generatedPaths, new Map(), analysisContext, sourceRoot));
        if (heredocHasDynamicExpansion(heredoc)) {
          unresolvedEvidence("Unquoted heredoc expansion cannot be resolved statically");
        }
      }
      for (const [argumentIndex, arg] of args.entries()) {
        if (inlineSourceIndexes.has(argumentIndex) || isStaticallyResolvedValue(arg) || /^(?:[A-Za-z][A-Za-z0-9+.-]*):\/\//.test(arg) || unresolvedPathArguments.has(arg)) continue;
        const expandedOperand = builtinCommandCategory(cmd) !== "allow" && !INTERPRETERS.has(cmd) && referencedShellVariables(command).some((name) => arg.includes(`$${name}`) || arg.includes(`\${${name}`));
        if (!arg.includes("/") && !expandedOperand && !arg.includes("__bash_guard_substitution_")) continue;
        unresolvedPathArguments.add(arg);
        unresolvedEvidence(`Dynamic path cannot be resolved statically: ${arg}`);
        pathExpansions.push({ expression: arg, matches: [], unresolved: true });
      }
      const catastrophic = catastrophicInvocation(cmd, args, cwd, this.policy.home);
      if (catastrophic) return this.result("deny", [`Catastrophic operation: ${catastrophic}`]);
      const informational = informationalInvocation(cmd, args);
      if (informational.handled) {
        if (executableRaw.includes("/")) {
          const executable = this.path(executableRaw, cwd);
          accesses.push({ path: executable, kind: "execute", source: `${cmd} information`, literal: isLiteralShellPath(executableRaw), existed: pathExists(executable) });
          mergeNested(this.screenScript(executable, cwd, undefined, sourceRoot));
        }
        for (const path of informational.readPaths) {
          if (!isStaticallyResolvedValue(path)) {
            unresolvedEvidence(`Dynamic informational read path cannot be checked safely: ${path}`);
            continue;
          }
          accesses.push({ path: this.path(path, cwd), kind: "read", source: `${cmd} information`, literal: isLiteralShellPath(path), existed: pathExists(this.path(path, cwd)) });
        }
        continue;
      }
      const pathLikeArgument = (value: string): boolean => !unresolvedPathArguments.has(value) &&
        (unmatchedGlobArguments.has(value) || looksLikePath(value) || pathExists(this.path(value, cwd)));
      const argumentAccess = (value: string, kind: AccessKind, source: string): PathAccess => {
        const unmatched = unmatchedGlobArguments.has(value);
        const path = this.path(value, cwd);
        return { path, kind, source, literal: unmatched || isLiteralShellPath(value), existed: unmatched ? false : pathExists(path) };
      };

      if (cmd === "npm") {
        const npm = selectNpmScripts(args, cwd);
        if (npm.handled) {
          if (npm.packageJson) {
            const packageJson = this.path(npm.packageJson, cwd);
            accesses.push({ path: packageJson, kind: "read", source: "npm script", literal: true, existed: pathExists(packageJson) });
          }
          if (npm.unresolvedReason || !npm.packageRoot || !npm.key) {
            const reason = npm.unresolvedReason ?? "npm script selection could not be resolved safely";
            if (npm.dynamicSelection) unresolvedEvidence(reason);
            else {
              baseDecision = strongest(baseDecision, "ask");
              reasons.push(reason);
            }
          } else if (this.npmScriptStack.has(npm.key)) {
            baseDecision = strongest(baseDecision, "ask");
            reasons.push(`Recursive npm script requires approval: ${npm.key.split("\0").at(-1)}`);
          } else {
            this.npmScriptStack.add(npm.key);
            try {
              for (const script of npm.scripts) {
                const source = script.appendArguments && npm.arguments.length
                  ? `${script.source} ${shellQuote(npm.arguments)}`
                  : script.source;
                for (const unit of this.analyzeCommandUnits(source, npm.packageRoot, "source")) {
                  mergeNested(unit.analysis);
                }
              }
            } finally { this.npmScriptStack.delete(npm.key); }
          }
          continue;
        }
      }

      if (cmd === "trap") {
        const trapArgs = args[0] === "--" ? args.slice(1) : args;
        if (!trapArgs.length || ["-l", "-p"].includes(trapArgs[0] ?? "") || ["-", ""].includes(trapArgs[0] ?? "")) continue;
        mergeNested(this.analyzeCommand(trapArgs[0]!, cwd, shellEnvironment, generatedPaths, new Map(), "source", sourceRoot));
        continue;
      }

      const gitInvocation = cmd === "git" ? parseGitInvocation(args) : undefined;
      if (gitInvocation && isDestructiveGitInvocation(gitInvocation)) {
        return this.result("deny", [`Destructive Git operation (${gitInvocation.subcommand}) is prohibited`]);
      }
      if (cmd === "git") {
        if (gitInvocation?.subcommand === "clone") {
          const clone = gitCloneArguments(gitInvocation.args);
          if (clone) {
            const repository = this.path(clone.repository, cwd);
            if (looksLikePath(clone.repository) || pathExists(repository)) {
              accesses.push({ path: repository, kind: "read", source: "git clone", literal: isLiteralShellPath(clone.repository), existed: pathExists(repository) });
            }
          }
          if (clone?.destination) {
            const path = this.path(clone.destination, cwd);
            if (isWithin(path, "/tmp") && !pathExists(path)) {
              creations.push(path);
              for (const binding of generatedPaths.values()) {
                if (!binding.discoveryPattern || (path !== binding.path && !isWithin(path, binding.path))) continue;
                creationPatterns.push(join(binding.discoveryPattern, relative(binding.path, path)));
              }
              continue;
            }
          }
        }
        const invocation = gitInvocation!;
        const readOnly = isReadOnlyGitOperation(invocation);
        if (!readOnly && !sourceInvocationIncomplete) {
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
        const categorized = this.analyzeCategorizedCommand("read", cmd, args, cwd, shellEnvironment, unmatchedGlobArguments, unresolvedPathArguments, generatedPaths, analysisContext, sourceRoot);
        baseDecision = strongest(baseDecision, categorized.decision);
        reasons.push(...categorized.reasons);
        accesses.push(...categorized.accesses);
        continue;
      }

      if (cmd === "nix-store" && isReadOnlyNixStoreQuery(args)) {
        const categorized = this.analyzeCategorizedCommand("read", cmd, args, cwd, shellEnvironment, unmatchedGlobArguments, unresolvedPathArguments, generatedPaths, analysisContext, sourceRoot);
        baseDecision = strongest(baseDecision, categorized.decision);
        reasons.push(...categorized.reasons);
        accesses.push(...categorized.accesses);
        continue;
      }

      if (cmd === "hyprctl") {
        if (!isReadOnlyHyprctl(args) && !sourceInvocationIncomplete) {
          baseDecision = strongest(baseDecision, "ask");
          reasons.push(`Mutative or unknown hyprctl command (${hyprctlCommand(args) ?? "hyprctl"}) requires approval`);
        }
        continue;
      }


      if (cmd === "curl") {
        const classification = classifyCurl(args);
        if (!classification.readOnly && !sourceInvocationIncomplete) {
          baseDecision = strongest(baseDecision, "ask");
          reasons.push("curl request may mutate remote state or uses opaque output options");
        }
        for (const output of classification.outputs) {
          if (output === "-") continue;
          if (!isStaticallyResolvedValue(output)) {
            unresolvedEvidence(`Dynamic curl output cannot be resolved statically: ${output}`);
            continue;
          }
          const lexicalOutput = literalPath(output, cwd);
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
        if (!safeQuery && !sourceInvocationIncomplete) {
          baseDecision = strongest(baseDecision, "ask");
          reasons.push("ipptool test may perform a mutative printer operation");
        }
        for (const arg of candidates.filter((value) => looksLikePath(value) || pathExists(this.path(value, cwd)))) {
          accesses.push({ path: this.path(arg, cwd), kind: "read", source: "ipptool", literal: isLiteralShellPath(arg) });
        }
        continue;
      }

      if (cmd === "systemctl") {
        if (!isReadOnlySystemctl(args) && !sourceInvocationIncomplete) {
          baseDecision = strongest(baseDecision, "ask");
          reasons.push("Mutative or unknown systemctl operation requires approval");
        }
        continue;
      }

      if (cmd === "rm" || cmd === "rmdir" || cmd === "unlink") {
        for (const arg of args.filter((value) => !value.startsWith("-"))) {
          if (!isStaticallyResolvedValue(arg)) {
            unresolvedEvidence(`Dynamic deletion target cannot be resolved statically: ${arg}`);
            continue;
          }
          if (!pathLikeArgument(arg)) continue;
          const access = argumentAccess(arg, "delete", cmd);
          accesses.push(access);
          if (access.literal) trashable.push(access.path);
        }
        continue;
      }

      if (["touch", "mkdir", "mktemp"].includes(cmd)) {
        for (const arg of args.filter((value) => !value.startsWith("-"))) {
          if (!isStaticallyResolvedValue(arg)) {
            unresolvedEvidence(`Dynamic creation target cannot be resolved statically: ${arg}`);
            continue;
          }
          const path = this.path(arg, cwd);
          if (pathExists(path)) accesses.push({ path, kind: "edit", source: cmd, literal: true, existed: true });
          else creations.push(path);
        }
        continue;
      }

      if (cmd === "tee") {
        for (const arg of args.filter((value) => !value.startsWith("-"))) {
          if (!isStaticallyResolvedValue(arg)) {
            unresolvedEvidence(`Dynamic tee target cannot be resolved statically: ${arg}`);
            continue;
          }
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
          const staticSources = sourceArgs.filter(isStaticallyResolvedValue);
          if (staticSources.length !== sourceArgs.length || !isStaticallyResolvedValue(destinationArg)) {
            unresolvedEvidence(`Dynamic ${cmd} path cannot be resolved statically`);
          }
          for (const source of staticSources) {
            accesses.push({ path: this.path(source, cwd), kind: "read", source: cmd, literal: true });
          }
          if (isStaticallyResolvedValue(destinationArg)) {
            const destination = this.path(destinationArg, cwd);
            const destinationIsDirectory = sourceArgs.length > 1 || /[/\\]$/.test(destinationArg) || pathIsDirectory(destination);
            const baseTargets = destinationIsDirectory
              ? staticSources.map((source) => canonicalPath(join(destination, basename(source))))
              : [destination];
            const recursive = args.some((arg) => arg === "--recursive" || /^-[^-]*[Rr]/.test(arg));
            const targets = staticSources.flatMap((source, index) => recursive
              ? recursiveCopyTargets(this.path(source, cwd), baseTargets[index] ?? destination)
              : [baseTargets[index] ?? destination]);
            if (!destinationIsDirectory && !staticSources.length) targets.push(destination);
            for (const target of new Set(targets)) {
              if (pathExists(target)) accesses.push({ path: target, kind: "edit", source: cmd, literal: true, existed: true });
              else creations.push(target);
            }
          }
        } else {
          baseDecision = strongest(baseDecision, "ask");
          reasons.push(`Unable to resolve ${cmd} targets`);
        }
        continue;
      }

      if (cmd === "mv") {
        const positional = args.filter((value) => !value.startsWith("-"));
        for (const value of positional) {
          if (!isStaticallyResolvedValue(value)) {
            unresolvedEvidence(`Dynamic mv path cannot be resolved statically: ${value}`);
            continue;
          }
          accesses.push({ path: this.path(value, cwd), kind: "edit", source: cmd, literal: true, existed: pathExists(this.path(value, cwd)) });
        }
        continue;
      }

      if (cmd === "xargs") {
        unresolvedEvidence("xargs executes a command with dynamically supplied arguments");
        const action = xargsNestedCommand(args);
        if (action?.length) {
          mergeNested(this.analyzeCommand(shellQuote(action), cwd, shellEnvironment, generatedPaths, new Map(), analysisContext, sourceRoot));
        }
        continue;
      }

      if (cmd === "find" && args.some((arg) => ["-delete", "-exec", "-execdir", "-ok", "-okdir"].includes(arg))) {
        const root = args[0] && !args[0].startsWith("-") ? args[0] : ".";
        const rootResolved = isStaticallyResolvedValue(root);
        if (!rootResolved) unresolvedEvidence(`Dynamic find root cannot be resolved statically: ${root}`);
        if (args.includes("-delete")) {
          if (rootResolved) {
            accesses.push({ path: this.path(root, cwd), kind: "delete", source: "find", literal: false, existed: pathExists(this.path(root, cwd)) });
          }
        } else {
          unresolvedEvidence("find -exec/-execdir/-ok/-okdir executes a nested command");
          if (rootResolved) {
            accesses.push({ path: this.path(root, cwd), kind: "read", source: "find", literal: isLiteralShellPath(root) });
          }
          for (let optionIndex = 0; optionIndex < args.length; optionIndex++) {
            if (!["-exec", "-execdir", "-ok", "-okdir"].includes(args[optionIndex] ?? "")) continue;
            const terminator = args.findIndex((arg, index) => index > optionIndex && [";", "+"].includes(arg));
            const action = args.slice(optionIndex + 1, terminator < 0 ? args.length : terminator)
              .map((arg) => arg === "{}" ? "__bash_guard_find_path__" : arg);
            if (!action.length) continue;
            mergeNested(this.analyzeCommand(shellQuote(action), cwd, shellEnvironment, generatedPaths, new Map(), analysisContext, sourceRoot));
            optionIndex = terminator < 0 ? args.length : terminator;
          }
        }
        continue;
      }

      const perlInPlace = cmd === "perl" && args.some((arg) => /^-[^-]*i/.test(arg) || arg === "--in-place" || arg.startsWith("--in-place="));
      if ((cmd === "sed" && args.some((arg) => arg === "-i" || arg.startsWith("-i"))) || perlInPlace) {
        const targets = cmd === "sed" ? sedInPlaceTargets(args) : args.filter((arg) => !arg.startsWith("-") && (looksLikePath(arg) || pathExists(this.path(arg, cwd))));
        for (const value of targets) {
          if (!isStaticallyResolvedValue(value)) {
            unresolvedEvidence(`Dynamic ${cmd} in-place target cannot be resolved statically: ${value}`);
            continue;
          }
          accesses.push({ path: this.path(value, cwd), kind: "edit", source: cmd, literal: true, existed: pathExists(this.path(value, cwd)) });
        }
        if (cmd === "sed") continue;
      }

      const luacParseOnly = cmd === "luac" && args.some((arg) => arg === "-p" || /^-[^-]*p/.test(arg)) &&
        !args.some((arg) => arg === "-o" || arg.startsWith("--output"));
      if (luacParseOnly) {
        const categorized = this.analyzeCategorizedCommand("read", cmd, args, cwd, shellEnvironment, unmatchedGlobArguments, unresolvedPathArguments, generatedPaths, analysisContext, sourceRoot);
        baseDecision = strongest(baseDecision, categorized.decision);
        reasons.push(...categorized.reasons);
        accesses.push(...categorized.accesses);
        continue;
      }

      if (INTERPRETERS.has(cmd)) {
        const supportedInlineSources = inlineSources.filter((source) => !source.opaque);
        if (cmd === "node" && !args.some((argument) => argument === "--test" || argument.startsWith("--test="))) {
          for (const preload of nodePreloads(args)) {
            if (preload.value === undefined || !isStaticallyResolvedValue(preload.value) || /^(?:data|https?):/i.test(preload.value)) {
              unresolvedEvidence(`${preload.source} target cannot be resolved safely`);
              continue;
            }
            if (!looksLikePath(preload.value) && !preload.value.startsWith("file:")) continue;
            const path = this.modulePath(preload.value, cwd, "javascript");
            accesses.push({ path, kind: "execute", source: preload.source, literal: true, existed: pathExists(path) });
            if (pathExists(path)) mergeNested(this.screenScript(path, cwd, "node", sourceRoot, "module"));
          }
        }
        if (cmd === "julia") {
          for (const preload of juliaPreloads(args)) {
            if (preload.value === undefined || !isStaticallyResolvedValue(preload.value)) {
              unresolvedEvidence(`${preload.source} target cannot be resolved safely`);
              continue;
            }
            const path = this.modulePath(preload.value, cwd, "julia");
            accesses.push({ path, kind: "execute", source: preload.source, literal: true, existed: pathExists(path) });
            if (pathExists(path)) mergeNested(this.screenScript(path, cwd, "julia", sourceRoot, "entry"));
          }
        }
        if (supportedInlineSources.length) {
          for (const inline of supportedInlineSources) {
            if (inline.source === undefined) unresolvedEvidence(`${cmd} inline source could not be resolved`);
            else mergeNested(this.screenSource(inline.source, inline.language, cwd, `inline ${cmd} source`, cwd, sourceRoot));
          }
          continue;
        }
        if (cmd === "node") {
          const tests = selectNodeTestFiles(args, cwd);
          if (tests.enabled) {
            if (tests.truncated) {
              baseDecision = strongest(baseDecision, "ask");
              reasons.push("Node test discovery exceeds 512 files and cannot be analyzed completely");
            }
            if (tests.unresolved) {
              unresolvedEvidence("Node test files could not be discovered safely");
            }
            for (const destination of tests.reporterDestinations) {
              if (!isStaticallyResolvedValue(destination)) {
                unresolvedEvidence(`Dynamic Node test reporter destination cannot be resolved statically: ${destination}`);
                continue;
              }
              const path = this.path(destination, cwd);
              if (pathExists(path)) accesses.push({ path, kind: "edit", source: "node --test reporter", literal: true, existed: true });
              else creations.push(path);
            }
            const testFiles = new Set(tests.files);
            for (const selected of new Set([...tests.supportFiles, ...tests.files])) {
              const path = this.path(selected, cwd);
              accesses.push({ path, kind: "execute", source: "node --test", literal: true, existed: pathExists(path) });
              mergeNested(this.screenScript(path, cwd, "node", sourceRoot, testFiles.has(selected) ? "entry" : "module"));
            }
            continue;
          }
        }
        if (heredocInputs.length && interpreterReadsStdin(cmd, args)) {
          const heredoc = heredocInputs.at(-1)!;
          const language: ScriptLanguage = SHELL_INTERPRETERS.has(cmd) ? "shell" : cmd === "node" ? "javascript" : ["python", "python3"].includes(cmd) ? "python" : cmd === "julia" ? "julia" : "other";
          if (language === "other") {
            baseDecision = strongest(baseDecision, "ask");
            reasons.push(`Opaque ${cmd} heredoc source requires approval`);
          } else mergeNested(this.screenSource(heredoc.source, language, cwd, `inline ${cmd} heredoc`, cwd, sourceRoot));
          continue;
        }
        if (["python", "python3"].includes(cmd)) {
          const moduleIndex = args.findIndex((argument) => argument === "-m" || /^-m.+/.test(argument));
          if (moduleIndex >= 0) {
            const module = args[moduleIndex] === "-m" ? args[moduleIndex + 1] : args[moduleIndex]!.slice(2);
            if (!module || !isStaticallyResolvedValue(module)) {
              unresolvedEvidence(`${cmd} module execution target cannot be resolved statically`);
              continue;
            }
            const path = this.modulePath(module.replaceAll(".", "/"), cwd, "python");
            if (pathExists(path)) {
              accesses.push({ path, kind: "execute", source: `${cmd} -m`, literal: true, existed: true });
              mergeNested(this.screenScript(path, cwd, "python", sourceRoot));
              continue;
            }
            baseDecision = strongest(baseDecision, "ask");
            reasons.push(`${cmd} module execution requires approval`);
            continue;
          }
        }
        if (cmd === "julia" && args.some((argument) => argument === "-m" || argument === "--module" || /^-m.+/.test(argument) || argument.startsWith("--module="))) {
          const module = juliaModuleArgument(args);
          if (!module || !isStaticallyResolvedValue(module)) {
            unresolvedEvidence("julia module execution target cannot be resolved statically");
            continue;
          }
          const path = this.modulePath(module.split(".")[0]!, cwd, "julia");
          if (pathExists(path)) {
            accesses.push({ path, kind: "execute", source: "julia -m", literal: true, existed: true });
            mergeNested(this.screenScript(path, cwd, "julia", sourceRoot));
            continue;
          }
          baseDecision = strongest(baseDecision, "ask");
          reasons.push("julia module execution requires approval");
          continue;
        }
        if (hasOpaqueInlineCode(cmd, args)) {
          baseDecision = strongest(baseDecision, "ask");
          reasons.push(`Opaque ${cmd} inline code requires approval`);
          continue;
        }
        const script = cmd === "julia" ? juliaScriptArgument(args) : interpreterScriptArgument(cmd, args);
        if (script) {
          if (!isStaticallyResolvedValue(script)) {
            unresolvedEvidence(`Dynamic ${cmd} script target cannot be resolved statically: ${script}`);
            continue;
          }
          const path = this.path(script, cwd);
          accesses.push({ path, kind: "execute", source: cmd, literal: isLiteralShellPath(script), existed: pathExists(path) });
          mergeNested(this.screenScript(path, cwd, cmd, sourceRoot));
        } else {
          baseDecision = strongest(baseDecision, "ask");
          reasons.push(`Opaque ${cmd} execution requires approval`);
        }
        continue;
      }

      if (analysisContext === "source" && !isStaticallyResolvedValue(executableRaw)) continue;
      if (executableRaw.includes("/")) {
        const executable = this.path(executableRaw, cwd);
        mergeNested(this.screenScript(executable, cwd, undefined, sourceRoot));
        if (this.policy.isSystemReadonlyPath(executable)) {
          const systemCategory = builtinCommandCategory(cmd);
          if (!systemCategory) {
            if (!sourceInvocationIncomplete) {
              baseDecision = strongest(baseDecision, "ask");
              reasons.push(`Unknown system command ${cmd} requires approval`);
            }
          } else {
            const categorized = this.analyzeCategorizedCommand(systemCategory, cmd, args, cwd, shellEnvironment, unmatchedGlobArguments, unresolvedPathArguments, generatedPaths, analysisContext, sourceRoot);
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
        const categorized = this.analyzeCategorizedCommand(category, cmd, args, cwd, shellEnvironment, unmatchedGlobArguments, unresolvedPathArguments, generatedPaths, analysisContext, sourceRoot);
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

      if (sourceInvocationIncomplete) {
        for (const arg of args.filter((value) => isStaticallyResolvedValue(value) && pathLikeArgument(value))) {
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

    const finalized = this.finalize(accesses, creations, trashable, reasons, generatedPaths);
    finalized.decision = strongest(finalized.decision, baseDecision);
    if (unknownCommands.length) finalized.unknownCommands = unknownCommands.filter((item, index, all) =>
      all.findIndex((candidate) => candidate.name === item.name &&
        candidate.arguments.length === item.arguments.length &&
        candidate.arguments.every((value, argIndex) => value === item.arguments[argIndex])) === index);
    if (pathExpansions.length) finalized.pathExpansions = pathExpansions.filter((item, index, all) =>
      all.findIndex((candidate) => candidate.expression === item.expression &&
        candidate.unresolved === item.unresolved && candidate.truncated === item.truncated &&
        candidate.matches.length === item.matches.length && candidate.matches.every((value, matchIndex) => value === item.matches[matchIndex])) === index);
    if (creationPatterns.length) finalized.creationPatterns = [...new Set(creationPatterns)].filter((path) => !path.startsWith(UNKNOWN_CWD));
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
    generatedPaths: GeneratedPathEnvironment = new Map(),
    analysisContext: AnalysisContext = "direct",
    sourceRoot = cwd,
  ): Analysis {
    if (category === "deny") return this.result("deny", [`Command ${command} is registered as prohibited`]);
    if (category === "allow") return this.result("allow", []);
    if (category === "remote") {
      return analysisContext === "source" && args.some((arg) => !isStaticallyResolvedValue(arg))
        ? this.result("allow", [])
        : this.result("ask", [`${command} may mutate remote or managed state`]);
    }

    if (category === "execute" && (command === "eval" || command === "source" || command === ".")) {
      if (command === "eval") return this.analyzeCommand(args.join(" "), cwd, shellEnvironment, generatedPaths, new Map(), "source", sourceRoot);
      const script = args.find((arg) => !arg.startsWith("-"));
      if (!script) return this.result("ask", [`${command} requires an execution target`]);
      if (!isStaticallyResolvedValue(script)) return analysisContext === "source"
        ? this.result("allow", [])
        : this.result("ask", [`Dynamic execution target cannot be resolved statically: ${script}`]);
      const access = this.analyzePathAccess(this.path(script, cwd), "execute", cwd, command);
      const path = this.path(script, cwd);
      return pathExists(path)
        ? combineAnalyses([access, this.screenScript(path, cwd, "bash", sourceRoot, "module")])
        : access;
    }

    const rawPositional = args.filter((arg) => !arg.startsWith("-"));
    const dynamicMutationTargets = rawPositional.filter((arg) => !isStaticallyResolvedValue(arg));
    const requireStaticMutationTargets = (analysis: Analysis): Analysis => {
      if (analysisContext === "direct" && ["create", "edit", "delete"].includes(category) && dynamicMutationTargets.length) {
        analysis.decision = strongest(analysis.decision, "ask");
        analysis.reasons.push(`${command} has dynamic mutation arguments that cannot be resolved statically: ${dynamicMutationTargets.join(", ")}`);
      }
      return analysis;
    };
    const positional = rawPositional.filter((arg) => !unresolvedPathArguments.has(arg) &&
      (["create", "edit", "delete"].includes(category) ? isStaticallyResolvedValue(arg) : true));
    const pathArguments = positional.filter((arg) => unmatchedGlobArguments.has(arg) || looksLikePath(arg) || pathExists(this.path(arg, cwd)));
    const pathAccess = (arg: string, kind: AccessKind): PathAccess => {
      const unmatched = unmatchedGlobArguments.has(arg);
      const path = this.path(arg, cwd);
      return { path, kind, source: command, literal: unmatched || isLiteralShellPath(arg), existed: unmatched ? false : pathExists(path) };
    };
    if (category === "read") {
      return this.finalize(pathArguments.map((arg) => pathAccess(arg, "read")), [], [], [], generatedPaths);
    }
    if (category === "create") {
      const accesses: PathAccess[] = [];
      const creations: string[] = [];
      for (const arg of positional) {
        const path = this.path(arg, cwd);
        if (pathExists(path)) accesses.push({ path, kind: "edit", source: command, literal: true, existed: true });
        else creations.push(path);
      }
      return requireStaticMutationTargets(this.finalize(accesses, creations, [], [], generatedPaths));
    }
    if (category === "edit") {
      return requireStaticMutationTargets(this.finalize(pathArguments.map((arg) => pathAccess(arg, "edit")), [], [], [], generatedPaths));
    }
    if (category === "delete") {
      const accesses = pathArguments.map((arg): PathAccess => pathAccess(arg, "delete"));
      const trashable = accesses.filter((item) => item.literal).map((item) => item.path);
      return requireStaticMutationTargets(this.finalize(accesses, [], trashable, [], generatedPaths));
    }
    // Execute-category tools may run arbitrary nested programs or build logic.
    const accesses = pathArguments.map((arg): PathAccess => pathAccess(arg, "execute"));
    const incompleteSourceExecution = analysisContext === "source" && args.some((arg) => !isStaticallyResolvedValue(arg));
    const result = this.finalize(accesses, [], [], incompleteSourceExecution ? [] : [`${command} may execute arbitrary logic`], generatedPaths);
    if (!incompleteSourceExecution) result.decision = strongest(result.decision, "ask");
    return result;
  }

  private sourceScreeningAnalysis(
    screening: SourceScreening,
    cwd: string,
    label: string,
    moduleBase = cwd,
    projectRoot = cwd,
  ): Analysis {
    if (screening.parseError) {
      return this.result("ask", [`${label} could not be inspected safely: ${screening.parseError}`]);
    }
    const accesses: PathAccess[] = [];
    const creations: string[] = [];
    for (const operation of screening.paths) {
      if (operation.path === undefined) continue;
      const path = this.path(operation.path, cwd);
      if (operation.kind === "read") {
        accesses.push({ path, kind: "read", source: operation.source, literal: true, existed: pathExists(path) });
      } else if (operation.kind === "delete") {
        accesses.push({ path, kind: "delete", source: operation.source, literal: true, existed: pathExists(path) });
      } else if (pathExists(path)) {
        accesses.push({ path, kind: "edit", source: operation.source, literal: true, existed: true });
      } else creations.push(path);
    }
    const analyses: Analysis[] = [this.finalize(accesses, creations, [], [])];
    for (const execution of screening.executions) {
      let executionCwd = execution.kind === "module" && execution.sourceRelative ? moduleBase : cwd;
      if (execution.dynamicCwd) {
        let hardReason: string | undefined;
        if (execution.kind === "shell" && execution.command !== undefined) {
          hardReason = this.analyzeCommandUnits(execution.command, cwd, "source", projectRoot)
            .flatMap((unit) => unit.analysis.reasons)
            .find((reason) => /^(?:Catastrophic operation|Destructive Git operation)/.test(reason));
        } else if (execution.kind === "argv" && execution.executable !== undefined) {
          const argumentsToAnalyze = (execution.args ?? []).map((argument, index) =>
            argument ?? `${SOURCE_DYNAMIC_ARGUMENT_PREFIX}${index}__`);
          hardReason = this.analyzeCommand(
            shellQuote([execution.executable, ...argumentsToAnalyze]),
            cwd,
            {},
            new Map(),
            new Map(),
            "source",
            projectRoot,
          ).reasons.find((reason) => /^(?:Catastrophic operation|Destructive Git operation)/.test(reason));
        }
        if (hardReason) analyses.push(this.result("deny", [hardReason]));
        continue;
      }
      if (execution.cwd) executionCwd = this.path(execution.cwd, cwd);
      if (execution.kind === "shell") {
        if (execution.command !== undefined) {
          analyses.push(...this.analyzeCommandUnits(execution.command, executionCwd, "source", projectRoot).map((unit) => unit.analysis));
        }
        continue;
      }
      if (execution.kind === "argv") {
        if (execution.executable !== undefined) {
          const dynamicArguments = execution.args === undefined || execution.args.some((argument) => argument === undefined);
          const argumentsToAnalyze = execution.args === undefined
            ? [`${SOURCE_DYNAMIC_ARGUMENT_PREFIX}0__`]
            : execution.args.map((argument, index) => argument ?? `${SOURCE_DYNAMIC_ARGUMENT_PREFIX}${index}__`);
          const nested = this.analyzeCommand(
            shellQuote([execution.executable, ...argumentsToAnalyze]),
            executionCwd,
            {},
            new Map(),
            new Map(),
            "source",
            projectRoot,
          );
          if (!dynamicArguments || nested.decision === "deny") {
            analyses.push(nested);
          } else {
            const evidence = this.finalize([...nested.accesses], [...nested.creationCandidates], [], []);
            evidence.creationPatterns = nested.creationPatterns;
            analyses.push(evidence);
          }
        }
        continue;
      }
      if (execution.path === undefined) continue;
      const modulePath = this.modulePath(execution.path, executionCwd, execution.language);
      analyses.push(this.finalize([{ path: modulePath, kind: "execute", source: execution.source, literal: true, existed: pathExists(modulePath) }], [], [], []));
      if (pathExists(modulePath)) analyses.push(this.screenScript(
        modulePath,
        cwd,
        execution.language === "python" ? "python" : execution.language === "julia" ? "julia" : "node",
        projectRoot,
        "module",
      ));
    }
    return combineAnalyses(analyses);
  }

  private screenSource(
    source: string,
    language: ScriptLanguage,
    cwd: string,
    label: string,
    moduleBase = cwd,
    projectRoot = cwd,
  ): Analysis {
    if (Buffer.byteLength(source, "utf8") > 262_144) {
      return this.result("ask", [`Executable source exceeds the 256 KiB inspection limit: ${label}`]);
    }
    const analyses: Analysis[] = [];
    try {
      if (language === "javascript") analyses.push(this.sourceScreeningAnalysis(javascriptExecutions(source), cwd, label, moduleBase, projectRoot));
      else if (language === "python") analyses.push(this.sourceScreeningAnalysis(pythonOperations(source), cwd, label, moduleBase, projectRoot));
      else if (language === "julia") analyses.push(this.sourceScreeningAnalysis(juliaOperations(source, {
        cwd,
        sourceDirectory: moduleBase,
        ...(pathExists(label) ? { sourceFile: label } : {}),
      }), cwd, label, moduleBase, projectRoot));
      else if (language === "shell") analyses.push(...this.analyzeCommandUnits(source, cwd, "source", projectRoot).map((unit) => unit.analysis));
      else {
        const catastrophic = catastrophicTextReason(source);
        if (catastrophic) analyses.push(this.result("deny", [`Prohibited script content: ${catastrophic}`]));
      }
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      analyses.push(this.result("ask", [`${label} source analysis failed closed: ${detail}`]));
    }

    if (language === "other") {
      const references = new Set<string>();
      for (const match of source.matchAll(/(?:~\/|\/|\.\.?\/)[^\s"'`;,|&()]+/g)) references.add(match[0]);
      for (const line of source.split("\n")) {
        if (line.trimStart().startsWith("#")) continue;
        try {
          for (const token of shellParse(line) as ParseToken[]) {
            if (typeof token === "string" && !token.startsWith("-")) references.add(token);
          }
        } catch { /* Unknown source retains conservative explicit path extraction. */ }
      }
      for (const reference of references) {
        const candidate = this.path(reference, cwd);
        if ((looksLikePath(reference) || pathExists(candidate)) && this.policy.isSecret(candidate)) {
          analyses.push(this.result("deny", [`Prohibited script content: secret reference ${candidate}`]));
        }
      }
    }
    return combineAnalyses(analyses);
  }

  private screenScript(
    path: string,
    cwd: string,
    interpreter?: string,
    projectRoot = cwd,
    role: SourceInspectionRole = "entry",
  ): Analysis {
    if (!pathExists(path)) return this.result("allow", []);
    if (!this.isInspectableSource(path, projectRoot, role)) return this.result("allow", []);
    const key = canonicalPath(path);
    if (this.screeningPaths.has(key)) return this.result("allow", []);
    this.screeningPaths.add(key);
    try {
      let source: string;
      try {
        if (statSync(path).size > 262_144) {
          return this.result("ask", [`Executable source exceeds the 256 KiB inspection limit: ${path}`]);
        }
        source = readFileSync(path, { encoding: "utf8", flag: "r" });
      } catch {
        // Binary or unreadable executables remain controlled by execute ownership.
        return this.result("allow", []);
      }
      try {
        return this.screenSource(source, scriptLanguage(path, interpreter, source), cwd, path, dirname(path), projectRoot);
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        return this.result("ask", [`Executable source analysis failed closed for ${path}: ${detail}`]);
      }
    } finally { this.screeningPaths.delete(key); }
  }

  private finalize(
    accesses: PathAccess[],
    creations: string[],
    trashable: string[],
    reasons: string[],
    generatedPaths: GeneratedPathEnvironment = new Map(),
  ): Analysis {
    const safeCreations: string[] = [];
    for (const path of creations) {
      if (isYoloControlPath(path) || this.policy.isPolicyPath(path) || this.policy.isSystemReadonlyPath(path) || containsGitMetadata(path)) {
        accesses.push({ path, kind: "edit", source: "creation", literal: true, existed: false });
      } else if (!path.startsWith(UNKNOWN_CWD)) safeCreations.push(path);
    }
    let decision: Decision = "allow";
    const ownershipCandidates: Analysis["ownershipCandidates"] = [];
    for (const access of accesses) {
      if (isYoloControlPath(access.path)) {
        decision = "deny";
        reasons.push(`Private bash-guard control state cannot be accessed by tools: ${access.path}`);
        continue;
      }
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
      if (access.path.startsWith(UNKNOWN_CWD)) continue;
      if (access.literal && ["read", "edit", "execute", "unknown"].includes(access.kind) && !(access.existed ?? pathExists(access.path))) continue;
      const generatedEdit = [...generatedPaths.values()].some((binding) =>
        binding.owned && (access.path === binding.path || (binding.directory && isWithin(access.path, binding.path))));
      const ownership = this.policy.ownership(access.path);
      const canEdit = generatedEdit || ownership === "edit" || ownership === "full";
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
      accesses: accesses.filter((access) => !access.path.startsWith(UNKNOWN_CWD)),
      creationCandidates: [...new Set(safeCreations)],
      trashablePaths: decision === "deny" ? [...new Set(trashable)].filter((path) => !path.startsWith(UNKNOWN_CWD)) : [],
      ownershipCandidates: ownershipCandidates.filter((item, index, all) => all.findIndex((x) => x.path === item.path && x.required === item.required) === index),
    };
  }

  private result(decision: Decision, reasons: string[], accesses: PathAccess[] = []): Analysis {
    return { decision, reasons, accesses, creationCandidates: [], trashablePaths: [], ownershipCandidates: [] };
  }
}
