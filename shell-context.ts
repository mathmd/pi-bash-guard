import { isAbsolute, resolve } from "node:path";
import { parse as shellParse, quote as shellQuote, type ParseToken } from "shell-quote";
import { canonicalPath, pathIsDirectory } from "./path-utils.ts";

/** Missing key = unknown; own undefined = unset; string = known (or an opaque $name). */
export const LOGICAL_DIRECTORY = Symbol("bash-guard.logical-directory");
export const OPAQUE_VARIABLE_WRITES = Symbol("bash-guard.opaque-variable-writes");
export const READONLY_VARIABLES = Symbol("bash-guard.readonly-variables");
export type ShellEnvironment = Record<string, string | undefined> & {
  [LOGICAL_DIRECTORY]?: string;
  [OPAQUE_VARIABLE_WRITES]?: boolean;
  [READONLY_VARIABLES]?: ReadonlySet<string>;
};
// NUL cannot occur in a real filesystem path; never conflate uncertainty with a user-owned path.
export const UNKNOWN_CWD = "/\0bash-guard-unknown-working-directory";
const NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const RUNTIME_NAMES = new Set(["RANDOM", "SRANDOM", "SECONDS", "EPOCHSECONDS", "EPOCHREALTIME", "LINENO", "BASHPID", "PPID", "_", "?", "!", "$", "#", "*", "@", "-"]);

export function copyShellEnvironment(environment: ShellEnvironment = {}): ShellEnvironment {
  return Object.assign(Object.create(null) as ShellEnvironment, environment);
}

export function knownShellValue(value: string | undefined): value is string {
  return value !== undefined && !/__bash_guard_(?:substitution|dynamic_data)_/.test(value) &&
    !/\$(?:[$?!#*@0-9-]|\(|\{|[A-Za-z_])|`/.test(value);
}

export function initialShellEnvironment(cwd: string, home: string, inherited: ShellEnvironment = {}): ShellEnvironment {
  const logical = inherited.PWD && isAbsolute(inherited.PWD) && canonicalPath(inherited.PWD) === canonicalPath(cwd) ? inherited.PWD : cwd;
  return copyShellEnvironment({ HOME: home, PWD: cwd, CDPATH: undefined, IFS: " \t\n", [LOGICAL_DIRECTORY]: logical, ...inherited });
}

export function shellValue(environment: ShellEnvironment, name: string): string | undefined {
  if (RUNTIME_NAMES.has(name) || !Object.hasOwn(environment, name)) return undefined;
  const value = environment[name];
  return value === undefined ? "" : knownShellValue(value) ? value : undefined;
}

/** Only scalar, non-mutating parameter operators. Unsupported syntax remains opaque. */
export function resolveShellParameter(key: string, environment: ShellEnvironment, depth = 0): string {
  const unknown = /^(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[$?!#*@-])$/.test(key) ? `$${key}` : `\${${key}}`;
  if (depth > 8) return unknown;
  if (NAME.test(key)) return shellValue(environment, key) ?? unknown;
  const match = key.match(/^([A-Za-z_][A-Za-z0-9_]*)(:?[-+])(.*)$/s);
  if (!match) return unknown;
  const [, name, operator, alternative] = match;
  if (!Object.hasOwn(environment, name!) || (environment[name!] !== undefined && shellValue(environment, name!) === undefined)) return unknown;
  const unset = environment[name!] === undefined || (operator!.startsWith(":") && environment[name!] === "");
  const useAlternative = operator!.endsWith("-") ? unset : !unset;
  if (!useAlternative) return operator!.endsWith("+") ? "" : shellValue(environment, name!) ?? unknown;
  // Do not interpret quotes, escapes, command substitutions, arithmetic, or pattern operators here.
  if (/[`'"\\\n]/.test(alternative!) || /\$\(/.test(alternative!)) return unknown;
  const expanded = alternative!.replace(/\$\{([^{}]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g,
    (_all, braced: string | undefined, bare: string | undefined) => resolveShellParameter(braced ?? bare!, environment, depth + 1));
  return knownShellValue(expanded) ? expanded : unknown;
}

/** Preserve raw word quoting for assignment evaluation; operators are not simple words. */
export function simpleShellWords(command: string): string[] | undefined {
  const words: string[] = [];
  let start = -1;
  let quote: "'" | '"' | undefined;
  let escaped = false;
  let braces = 0;
  for (let i = 0; i < command.length; i++) {
    const c = command[i]!;
    if (escaped) { escaped = false; continue; }
    if (c === "\\" && quote !== "'") { if (start < 0) start = i; escaped = true; continue; }
    if (quote) { if (c === quote) quote = undefined; continue; }
    if (c === "'" || c === '"') { if (start < 0) start = i; quote = c; continue; }
    if (c === "$" && command[i + 1] === "{") { braces++; if (start < 0) start = i; i++; continue; }
    if (c === "}" && braces) { braces--; continue; }
    if (braces) continue;
    if (c === "#" && start < 0) break;
    const redirect = command.slice(i).match(/^(?:&>>?|<<<|>>|>&|<&|>|<)/)?.[0];
    if (redirect) {
      const prefix = start < 0 ? "" : command.slice(start, i);
      if (prefix && !/^\d+$/.test(prefix)) words.push(prefix);
      words.push((/^\d+$/.test(prefix) ? prefix : "") + redirect);
      i += redirect.length - 1; start = -1; continue;
    }
    if (/[;&|<>()`]/.test(c)) return undefined;
    if (/\s/.test(c)) {
      if (start >= 0) words.push(command.slice(start, i));
      start = -1;
    } else if (start < 0) start = i;
  }
  if (quote || escaped || braces) return undefined;
  if (start >= 0) words.push(command.slice(start));
  return words;
}

/** Avoid shell-quote's ambiguous unbraced special-parameter/identifier scanning (notably $_name). */
function normalizeSimpleParameters(command: string): string {
  let result = "";
  let quote: "'" | '"' | undefined;
  for (let i = 0; i < command.length; i++) {
    const char = command[i]!;
    if (char === "\\" && quote !== "'") { result += command.slice(i, i + 2); i++; continue; }
    if (char === "'" || char === '"') {
      if (!quote) quote = char; else if (quote === char) quote = undefined;
    }
    if (char === "$" && quote !== "'") {
      const name = command.slice(i + 1).match(/^(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]|[$?!#*@-])/)?.[0];
      if (name) { result += `\${${name}}`; i += name.length; continue; }
    }
    result += char;
  }
  return result;
}

export function shellParameterNames(command: string): string[] {
  const names = new Set<string>();
  const inspect = (key: string): string => {
    const name = key.match(/^([A-Za-z_][A-Za-z0-9_]*)/)?.[1];
    if (name) names.add(name);
    for (const match of key.matchAll(/\$\{?([A-Za-z_][A-Za-z0-9_]*)/g)) names.add(match[1]!);
    return `$${key}`;
  };
  try { shellParse(normalizeSimpleParameters(command), inspect); } catch { /* The caller retains the syntax failure. */ }
  return [...names];
}

function parameterAt(command: string, index: number): string | undefined {
  if (command.slice(index, index + 2) !== "${") return undefined;
  let depth = 1;
  for (let end = index + 2; end < command.length; end++) {
    if (command.slice(end, end + 2) === "${") { depth++; end++; }
    else if (command[end] === "}" && --depth === 0) return command.slice(index + 2, end);
  }
  return undefined;
}

/** shell-quote does not model Bash field splitting/globbing of expanded values. Do not guess. */
export function parseShell(command: string, environment: ShellEnvironment): ParseToken[] {
  command = normalizeSimpleParameters(command);
  const unsafe = new Set<string>();
  let quote: "'" | '"' | undefined;
  let escaped = false;
  let wordStart = 0;
  let prepared = "";
  for (let i = 0; i < command.length; i++) {
    const c = command[i]!;
    if (escaped) { prepared += c; escaped = false; continue; }
    if (c === "\\" && quote !== "'") { prepared += c; escaped = true; continue; }
    if (c === "'" || c === '"') {
      if (!quote) quote = c;
      else if (quote === c) quote = undefined;
      prepared += c;
      continue;
    }
    if (!quote && /[\s;|&()]/.test(c)) wordStart = i + 1;
    const assignmentStart = /^[A-Za-z_][A-Za-z0-9_]*=$/.test(command.slice(wordStart, i));
    if (!quote && c === "~" && (i === wordStart || assignmentStart)) {
      const plainHome = command[i + 1] === "/" || !command[i + 1] || /[\s;|&<>]/.test(command[i + 1]!);
      const home = plainHome && environment.HOME !== undefined ? shellValue(environment, "HOME") : undefined;
      prepared += home === undefined ? "__bash_guard_dynamic_data_tilde__/" : shellQuote([home]);
      continue;
    }
    if (!quote && c === "$" && !/^[A-Za-z_][A-Za-z0-9_]*=/.test(command.slice(wordStart, i))) {
      const key = parameterAt(command, i);
      if (key !== undefined) {
        const value = resolveShellParameter(key, environment);
        const ifs = Object.hasOwn(environment, "IFS") && environment.IFS === undefined ? " \t\n" : shellValue(environment, "IFS");
        if (knownShellValue(value) && (!value || ifs === undefined || [...value].some((char) => ifs.includes(char)) || /[*?\[\]]/.test(value))) unsafe.add(key);
      }
    }
    prepared += c;
  }
  return shellParse(prepared, (key) => unsafe.has(key) ? `\${${key}}` : resolveShellParameter(key, environment)) as ParseToken[];
}

export interface AssignmentEffects {
  updates: ShellEnvironment;
  readonly: string[];
}

/** Evaluate assignment-only commands left-to-right. Prefix assignments to a child do not persist. */
export function assignmentEffects(command: string, environment: ShellEnvironment, readonlyNames = new Set<string>()): AssignmentEffects | undefined {
  const rawWords = simpleShellWords(command.replace(/\\\r?\n/g, ""));
  if (!rawWords?.length) return undefined;
  const words: string[] = [];
  for (let i = 0; i < rawWords.length; i++) {
    if (/^(?:\d*|&)(?:[<>]|>>|<&|>&|<<<)$/.test(rawWords[i]!)) { i++; continue; }
    words.push(rawWords[i]!);
  }
  while (["then", "else", "do", "{"].includes(words[0] ?? "")) words.shift();
  const declaration = ["export", "readonly", "declare", "typeset", "local"].includes(words[0] ?? "") ? words.shift() : undefined;
  const flags: string[] = [];
  while (declaration && words[0]?.startsWith("-")) flags.push(words.shift()!);
  const scalar = flags.every((flag) => flag === "--" || (declaration === "export" ? /^-n$/.test(flag) : declaration === "readonly" ? false : /^-[xr]+$/.test(flag)));
  const updates = copyShellEnvironment();
  const readonly: string[] = [];
  const current = copyShellEnvironment(environment);
  for (const word of words) {
    const match = word.match(/^([A-Za-z_][A-Za-z0-9_]*)(\+?=)(.*)$/s);
    if (!match) {
      if (!declaration || !NAME.test(word)) return undefined;
      if (!scalar || declaration === "local") updates[word] = `$${word}`;
      if (declaration === "readonly" || flags.some((flag) => flag.includes("r"))) readonly.push(word);
      continue;
    }
    const [, name, operator, raw] = match;
    if (readonlyNames.has(name!)) continue;
    let value: string | undefined;
    try {
      const expanded = parseShell(`value=${raw}`, declaration ? environment : current);
      if (expanded.length === 1 && typeof expanded[0] === "string") value = expanded[0].slice("value=".length);
    } catch { /* Unknown RHS poisons the old value, rather than retaining it. */ }
    if (operator === "+=") {
      const prior = shellValue(current, name!);
      value = prior !== undefined && value !== undefined ? prior + value : undefined;
    }
    updates[name!] = scalar && !environment[OPAQUE_VARIABLE_WRITES] && value !== undefined && !value.includes("__bash_guard_substitution_") ? value : `$${name}`;
    current[name!] = updates[name!];
    if (declaration === "readonly" || flags.some((flag) => flag.includes("r"))) readonly.push(name!);
  }
  return { updates, readonly };
}

/** Locate the current-shell builtin without mistaking redirections or invocation wrappers for it. */
function stateCommand(command: string, environment: ShellEnvironment): { words: string[]; prefixed: boolean } {
  const raw = simpleShellWords(command);
  if (raw) {
    const retained: string[] = [];
    for (let i = 0; i < raw.length; i++) {
      if (/^(?:\d*|&)(?:[<>]|>>|<&|>&|<<<)$/.test(raw[i]!)) i++;
      else retained.push(raw[i]!);
    }
    command = retained.join(" ");
  }
  let words: string[];
  try { words = parseShell(command, environment).map((token) => typeof token === "string" ? token : "$__bash_guard_unknown_operand"); }
  catch { words = []; }
  while (["then", "else", "do", "{", "!"].includes(words[0] ?? "")) words.shift();
  let prefixed = false;
  while (/^[A-Za-z_][A-Za-z0-9_]*\+?=/.test(words[0] ?? "")) { prefixed = true; words.shift(); }
  while (["builtin", "command"].includes(words[0] ?? "")) {
    const wrapper = words.shift();
    if (wrapper === "command" && words[0] === "-p") words.shift();
    if (wrapper === "command" && ["-v", "-V"].includes(words[0] ?? "")) return { words: [], prefixed };
    if (words[0] === "--") words.shift();
  }
  return { words, prefixed };
}

function mutatingShellParameters(command: string, environment: ShellEnvironment): string[] {
  const names = new Set<string>();
  try {
    shellParse(command, (key) => {
      for (const match of key.matchAll(/(?:^|\$\{)([A-Za-z_][A-Za-z0-9_]*)(:?=)/g)) {
        const name = match[1]!;
        const value = shellValue(environment, name);
        if (!Object.hasOwn(environment, name) || environment[name] === undefined || value === undefined || (match[2] === ":=" && value === "")) names.add(name);
      }
      return `$${key}`;
    });
  } catch { /* The analyzer handles syntax failures. */ }
  return [...names];
}

/** Current-shell operations whose variable effects are not statically interpreted. */
export function invalidateShellEffects(command: string, environment: ShellEnvironment, readonlyNames = new Set<string>()): Set<string> {
  const changed = new Set<string>();
  const [name, ...args] = stateCommand(command, environment).words;
  const poison = (key: string) => { if (!readonlyNames.has(key)) { environment[key] = `$${key}`; changed.add(key); } };
  const setter = ["export", "readonly", "declare", "typeset", "local", "unset", "read", "mapfile", "readarray", "getopts"].includes(name ?? "") || (name === "printf" && args.includes("-v"));
  const unknownSetter = setter && args.some((arg) => !knownShellValue(arg));
  const changesAttributes = ["declare", "typeset", "local"].includes(name ?? "") && args.some((arg) => /^-[^-]*[ni]/.test(arg));
  const indexedAssignment = /^(?:(?:then|do|else)\s+)?[A-Za-z_][A-Za-z0-9_]*\[/.test(command.trim());
  const changesDirectoryMode = name === "set" && args.some((arg) => /^[-+][A-Za-z]*P/.test(arg) || ["physical", "posix"].includes(arg) || !knownShellValue(arg));
  const opaqueShell = changesDirectoryMode || ["source", ".", "eval"].includes(name ?? "") || /^(?:function\s+\w+|\w+\s*\(\s*\))/.test(command.trim());
  if (opaqueShell || changesAttributes || indexedAssignment || unknownSetter || name === "let" || /^\(\(/.test(command.trim())) {
    for (const key of Object.keys(environment)) poison(key);
    environment[OPAQUE_VARIABLE_WRITES] = true;
    if (opaqueShell) { poison("PWD"); poison("OLDPWD"); environment[LOGICAL_DIRECTORY] = UNKNOWN_CWD; }
  } else if (name === "unset" && !args.includes("-f")) {
    for (const key of args.filter((arg) => NAME.test(arg) && !readonlyNames.has(arg))) { environment[key] = undefined; changed.add(key); }
  } else if (["read", "readarray", "mapfile", "getopts"].includes(name ?? "")) {
    // Options have different arities; poisoning an extra name is safer than retaining stale data.
    for (const key of args.filter((arg) => NAME.test(arg))) poison(key);
    if (name === "read") poison("REPLY");
    if (name === "getopts") poison("OPTARG");
    if (name === "mapfile" || name === "readarray") poison("MAPFILE");
  } else if (name === "printf" && args.includes("-v")) {
    const key = args[args.indexOf("-v") + 1];
    if (key && NAME.test(key)) poison(key);
  }
  if (["export", "readonly", "declare", "typeset", "local"].includes(name ?? "") && !assignmentEffects(command, environment, readonlyNames)) {
    if (name !== "export") environment[OPAQUE_VARIABLE_WRITES] = true;
    for (const arg of args) {
      const key = arg.match(/^([A-Za-z_][A-Za-z0-9_]*)(?:\+?=|$)/)?.[1];
      if (key) poison(key);
    }
  }
  if (["pushd", "popd"].includes(name ?? "")) {
    poison("PWD"); poison("OLDPWD"); environment[LOGICAL_DIRECTORY] = UNKNOWN_CWD;
  }
  for (const name of mutatingShellParameters(command, environment)) poison(name);
  return changed;
}

export function mergeShellEnvironments(environments: ShellEnvironment[]): ShellEnvironment {
  const merged = copyShellEnvironment();
  for (const key of new Set(environments.flatMap(Object.keys))) {
    const first = environments[0]!;
    merged[key] = environments.every((env) => Object.hasOwn(env, key) === Object.hasOwn(first, key) && env[key] === first[key])
      ? first[key] : `$${key}`;
  }
  const logical = environments[0]?.[LOGICAL_DIRECTORY];
  if (logical !== undefined) merged[LOGICAL_DIRECTORY] = environments.every((env) => env[LOGICAL_DIRECTORY] === logical) ? logical : UNKNOWN_CWD;
  if (environments.some((env) => env[OPAQUE_VARIABLE_WRITES])) merged[OPAQUE_VARIABLE_WRITES] = true;
  return merged;
}

export interface DirectoryChange { cwd: string; logical: string; }
export function shellDirectoryChange(command: string, cwd: string, environment: ShellEnvironment, isDirectory = pathIsDirectory): DirectoryChange | undefined {
  const { words: tokens, prefixed } = stateCommand(command, environment);
  if (tokens[0] !== "cd") return undefined;
  if (prefixed) return { cwd: UNKNOWN_CWD, logical: "$PWD" };
  if (environment[OPAQUE_VARIABLE_WRITES] && environment[LOGICAL_DIRECTORY] === UNKNOWN_CWD) return { cwd: UNKNOWN_CWD, logical: "$PWD" };
  let physical = false;
  let index = 1;
  while (["-L", "-P", "-e", "-@"].includes(tokens[index] ?? "")) {
    if (tokens[index] === "-L") physical = false;
    if (tokens[index] === "-P") physical = true;
    index++;
  }
  if (tokens[index] === "--") index++;
  let target: string | undefined = tokens[index] ?? shellValue(environment, "HOME");
  if (target === "-") target = shellValue(environment, "OLDPWD");
  if (!knownShellValue(target) || !target || tokens[index + 1] !== undefined) return { cwd: UNKNOWN_CWD, logical: "$PWD" };
  const cdpath = shellValue(environment, "CDPATH");
  if (!isAbsolute(target) && !/^\.\.?($|\/)/.test(target) && (cdpath === undefined || cdpath !== "")) {
    return { cwd: UNKNOWN_CWD, logical: "$PWD" };
  }
  const logicalBase = environment[LOGICAL_DIRECTORY];
  const validLogicalBase = logicalBase && isAbsolute(logicalBase) && canonicalPath(logicalBase) === cwd;
  if (!isAbsolute(target) && cwd === UNKNOWN_CWD) return { cwd: UNKNOWN_CWD, logical: "$PWD" };
  const physicalTarget = isAbsolute(target) ? target : `${cwd}/${target}`;
  if (physical && !isDirectory(physicalTarget)) return { cwd: UNKNOWN_CWD, logical: "$PWD" };
  const logical = physical ? canonicalPath(physicalTarget) : resolve(validLogicalBase ? logicalBase : cwd, target);
  const resolved = canonicalPath(logical);
  return isDirectory(resolved) ? { cwd: resolved, logical } : { cwd: UNKNOWN_CWD, logical: "$PWD" };
}
