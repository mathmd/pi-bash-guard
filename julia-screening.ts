import { basename, dirname, join, normalize, relative, resolve } from "node:path";
import Parser from "tree-sitter";
import Julia from "tree-sitter-julia";
import { parse as shellParse, quote as shellQuote, type ParseToken } from "shell-quote";
import type { SourceExecution, SourcePathOperation, SourceScreening } from "./source-operations.ts";

const MAX_SOURCE_OPERATIONS = 1_024;
const DYNAMIC_COMMAND_PART = "__bash_guard_julia_dynamic_";

const parser = new Parser();
parser.setLanguage(Julia);

type SyntaxNode = Parser.SyntaxNode;

interface JuliaContext {
  cwd: string;
  sourceDirectory: string;
  sourceFile?: string;
  strings: Map<string, string>;
  arrays: Map<string, Array<string | undefined>>;
  commands: Map<string, ResolvedCommand[]>;
}

interface ResolvedCommand {
  argv: Array<string | undefined>;
  cwd?: string;
  dynamicCwd?: boolean;
}

interface JuliaArguments {
  positional: SyntaxNode[];
  keywords: Map<string, SyntaxNode>;
}

const READ_FUNCTIONS = new Set([
  "countlines", "eachline", "filesize", "filemode", "isdir", "isfile", "islink", "ismount", "ispath",
  "lstat", "mtime", "ctime", "read", "readchomp", "readdir", "readline", "readlines", "readlink",
  "realpath", "samefile", "stat", "walkdir",
]);
const WRITE_FUNCTIONS = new Set(["chmod", "chown", "lchown", "mkdir", "mkpath", "touch", "truncate"]);
const DELETE_FUNCTIONS = new Set(["rm"]);
const COPY_FUNCTIONS = new Set(["cp"]);
const RENAME_FUNCTIONS = new Set(["mv"]);
const PROCESS_FUNCTIONS = new Set(["run", "success"]);
const PROCESS_OR_READ_FUNCTIONS = new Set(["eachline", "open", "read", "readchomp", "readline", "readlines"]);
const COMMAND_WRAPPERS = new Set(["addenv", "detach", "ignorestatus", "setenv"]);
const BASE_PREFIXES = new Set(["Base", "Base.Filesystem", "Filesystem"]);
const RECOGNIZED_DIRECT_FUNCTIONS = new Set([
  ...READ_FUNCTIONS, ...WRITE_FUNCTIONS, ...DELETE_FUNCTIONS, ...COPY_FUNCTIONS, ...RENAME_FUNCTIONS,
  ...PROCESS_FUNCTIONS, ...PROCESS_OR_READ_FUNCTIONS, "download", "hardlink", "include", "include_dependency",
  "mktemp", "mktempdir", "symlink", "write",
]);

function walk(node: SyntaxNode, visit: (node: SyntaxNode) => void): void {
  visit(node);
  for (const child of node.namedChildren) walk(child, visit);
}

function directIdentifier(node: SyntaxNode | null | undefined): string | undefined {
  return node?.type === "identifier" ? node.text : undefined;
}

function callParts(node: SyntaxNode): { callee?: SyntaxNode; args?: SyntaxNode; doClause?: SyntaxNode } {
  if (node.type !== "call_expression") return {};
  return {
    callee: node.namedChildren[0],
    args: node.namedChildren.find((child) => child.type === "argument_list"),
    doClause: node.namedChildren.find((child) => child.type === "do_clause"),
  };
}

function expressionName(node: SyntaxNode | null | undefined): string | undefined {
  if (!node) return undefined;
  if (node.type === "identifier") return node.text;
  if (node.type !== "field_expression") return undefined;
  const parts = node.namedChildren.map(expressionName);
  return parts.every((part) => part !== undefined) ? parts.join(".") : undefined;
}

function parseArguments(node: SyntaxNode | undefined): JuliaArguments {
  const positional: SyntaxNode[] = [];
  const keywords = new Map<string, SyntaxNode>();
  if (!node) return { positional, keywords };
  for (const child of node.namedChildren) {
    if (child.type !== "named_argument") {
      positional.push(child);
      continue;
    }
    const nameNode = child.namedChildren.find((part) => part.type === "identifier");
    const value = child.namedChildren.at(-1);
    if (nameNode && value && value !== nameNode) keywords.set(nameNode.text, value);
  }
  return { positional, keywords };
}

function decodeEscape(raw: string): string | undefined {
  if (!raw.startsWith("\\")) return raw;
  const body = raw.slice(1);
  const simple: Record<string, string> = {
    "\\": "\\", "\"": "\"", "'": "'", n: "\n", r: "\r", t: "\t", b: "\b", f: "\f", v: "\v", a: "\x07", e: "\x1b",
  };
  if (body in simple) return simple[body];
  if (body === "\n") return "";
  const unicode = body.match(/^(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4})|U([0-9a-fA-F]{8}))$/);
  if (unicode) return String.fromCodePoint(Number.parseInt(unicode[1] ?? unicode[2] ?? unicode[3]!, 16));
  const octal = body.match(/^[0-7]{1,3}$/)?.[0];
  return octal ? String.fromCodePoint(Number.parseInt(octal, 8)) : undefined;
}

function macroName(node: SyntaxNode): string | undefined {
  if (node.type !== "macrocall_expression") return undefined;
  return node.namedChildren.find((child) => child.type === "macro_identifier")?.text;
}

function functionLeaf(name: string | undefined): { name?: string; qualified: boolean; supported: boolean } {
  if (!name) return { qualified: false, supported: false };
  const parts = name.split(".");
  const leaf = parts.at(-1)!;
  if (parts.length === 1) return { name: leaf, qualified: false, supported: true };
  const prefix = parts.slice(0, -1).join(".");
  return { name: leaf, qualified: true, supported: BASE_PREFIXES.has(prefix) };
}

function booleanValue(node: SyntaxNode | undefined): boolean | undefined {
  if (node?.type !== "boolean_literal") return undefined;
  return node.text === "true";
}

function staticString(node: SyntaxNode | undefined, context: JuliaContext, depth = 0): string | undefined {
  if (!node || depth > 20) return undefined;
  if (["integer_literal", "float_literal", "boolean_literal"].includes(node.type)) return node.text;
  if (node.type === "identifier") return context.strings.get(node.text);
  const macro = macroName(node);
  if (macro === "@__DIR__") return context.sourceDirectory;
  if (macro === "@__FILE__") return context.sourceFile;
  if (node.type === "parenthesized_expression") {
    return staticString(node.namedChildren[0], context, depth + 1);
  }
  if (node.type === "string_literal") {
    let value = "";
    for (const child of node.namedChildren) {
      if (child.type === "content") value += child.text;
      else if (child.type === "escape_sequence") {
        const decoded = decodeEscape(child.text);
        if (decoded === undefined) return undefined;
        value += decoded;
      } else if (child.type === "string_interpolation") {
        const interpolated = staticString(child.namedChildren.at(-1), context, depth + 1);
        if (interpolated === undefined) return undefined;
        value += interpolated;
      }
    }
    return value;
  }
  if (node.type === "prefixed_string_literal") {
    if (node.namedChildren[0]?.text !== "raw") return undefined;
    return node.namedChildren.slice(1).map((child) => child.text).join("");
  }
  if (node.type === "binary_expression") {
    const operator = node.namedChildren.find((child) => child.type === "operator")?.text;
    const operands = node.namedChildren.filter((child) => child.type !== "operator");
    const left = staticString(operands[0], context, depth + 1);
    const right = staticString(operands[1], context, depth + 1);
    if (left === undefined || right === undefined) return undefined;
    if (operator === "*") return left + right;
    if (operator === "/") return join(left, right);
    return undefined;
  }
  if (node.type !== "call_expression") return undefined;
  const { callee, args: argNode } = callParts(node);
  const name = expressionName(callee)?.split(".").at(-1);
  const args = parseArguments(argNode).positional;
  const values = args.map((argument) => staticString(argument, context, depth + 1));
  if (name === "joinpath" && values.length && values.every((value) => value !== undefined)) return join(...values as string[]);
  if (name === "string" && values.every((value) => value !== undefined)) return values.join("");
  if (name === "abspath" && values.length && values.every((value) => value !== undefined)) return resolve(context.cwd, ...values as string[]);
  if (name === "normpath" && values.length === 1 && values[0] !== undefined) return normalize(values[0]);
  if (name === "dirname" && values.length === 1 && values[0] !== undefined) return dirname(values[0]);
  if (name === "basename" && values.length === 1 && values[0] !== undefined) return basename(values[0]);
  if (name === "relpath" && values[0] !== undefined) return relative(values[1] ?? context.cwd, values[0]);
  if (name === "pwd" && !args.length) return context.cwd;
  if (["identity", "normpath"].includes(name ?? "") && values.length === 1) return values[0];
  return undefined;
}

function staticArray(node: SyntaxNode | undefined, context: JuliaContext): Array<string | undefined> | undefined {
  if (!node) return undefined;
  if (node.type === "identifier") return context.arrays.get(node.text);
  if (!["vector_expression", "tuple_expression", "open_tuple"].includes(node.type)) return undefined;
  return node.namedChildren.map((child) => staticString(child, context));
}

function commandTokens(node: SyntaxNode, context: JuliaContext): Array<string | undefined> | undefined {
  if (node.type !== "command_literal") return undefined;
  let rendered = "";
  let dynamicIndex = 0;
  for (const child of node.namedChildren) {
    if (child.type === "content") rendered += child.text;
    else if (child.type === "escape_sequence") {
      const decoded = decodeEscape(child.text);
      if (decoded === undefined) return undefined;
      rendered += decoded;
    } else if (child.type === "string_interpolation") {
      const expression = child.namedChildren.at(-1);
      const values = staticArray(expression, context);
      if (values) {
        rendered += values.map((value) => value === undefined
          ? `${DYNAMIC_COMMAND_PART}${dynamicIndex++}__`
          : shellQuote([value])).join(" ");
      } else {
        const value = staticString(expression, context);
        rendered += value === undefined ? `${DYNAMIC_COMMAND_PART}${dynamicIndex++}__` : shellQuote([value]);
      }
    }
  }
  let parsed: ParseToken[];
  try { parsed = shellParse(rendered) as ParseToken[]; }
  catch { return undefined; }
  const words: Array<string | undefined> = [];
  for (const token of parsed) {
    let value: string | undefined;
    if (typeof token === "string") value = token;
    else if ("pattern" in token && typeof token.pattern === "string") value = token.pattern;
    else if ("op" in token && typeof token.op === "string") value = token.op;
    else return undefined;
    words.push(value.includes(DYNAMIC_COMMAND_PART) ? undefined : value);
  }
  return words.length ? words : undefined;
}

function commandValues(node: SyntaxNode | undefined, context: JuliaContext, depth = 0): ResolvedCommand[] | undefined {
  if (!node || depth > 20) return undefined;
  if (node.type === "command_literal") {
    const argv = commandTokens(node, context);
    return argv ? [{ argv }] : undefined;
  }
  if (node.type === "identifier") return context.commands.get(node.text);
  if (node.type === "parenthesized_expression") return commandValues(node.namedChildren[0], context, depth + 1);
  if (node.type !== "call_expression") return undefined;
  const { callee, args: argNode } = callParts(node);
  const name = expressionName(callee)?.split(".").at(-1);
  const args = parseArguments(argNode);
  if (name === "pipeline") {
    const commands = args.positional.flatMap((argument) => commandValues(argument, context, depth + 1) ?? []);
    return commands.length ? commands : undefined;
  }
  if (name === "Cmd") {
    const nested = commandValues(args.positional[0], context, depth + 1);
    const array = staticArray(args.positional[0], context);
    const commands = nested ?? (array ? [{ argv: array }] : undefined);
    if (!commands) return undefined;
    const cwdNode = args.keywords.get("dir");
    if (!cwdNode) return commands;
    const cwd = staticString(cwdNode, context);
    return commands.map((command) => ({ ...command, ...(cwd ? { cwd } : { dynamicCwd: true }) }));
  }
  if (COMMAND_WRAPPERS.has(name ?? "")) return commandValues(args.positional[0], context, depth + 1);
  return undefined;
}

function isCommandExpression(node: SyntaxNode | undefined, context: JuliaContext): boolean {
  if (!node) return false;
  if (node.type === "command_literal") return true;
  if (node.type === "identifier") return context.commands.has(node.text);
  if (node.type !== "call_expression") return false;
  const name = expressionName(callParts(node).callee)?.split(".").at(-1);
  return name === "Cmd" || name === "pipeline" || COMMAND_WRAPPERS.has(name ?? "");
}

function assignmentParts(node: SyntaxNode): { name?: string; value?: SyntaxNode; functionName?: string } {
  if (node.type !== "assignment") return {};
  const operands = node.namedChildren.filter((child) => child.type !== "operator");
  const left = operands[0];
  const right = operands.at(-1);
  if (!left || !right || left === right) return {};
  if (left.type === "identifier") return { name: left.text, value: right };
  if (left.type === "call_expression") return { functionName: directIdentifier(callParts(left).callee) };
  return {};
}

function functionDefinitionName(node: SyntaxNode): string | undefined {
  if (node.type !== "function_definition") return undefined;
  const signature = node.namedChildren.find((child) => child.type === "signature");
  const call = signature?.namedChildren.find((child) => child.type === "call_expression");
  return directIdentifier(call ? callParts(call).callee : undefined);
}

function builtinCall(name: string | undefined, locallyBound: Set<string>): string | undefined {
  const leaf = functionLeaf(name);
  if (!leaf.supported || !leaf.name) return undefined;
  return leaf.qualified || !locallyBound.has(leaf.name) ? leaf.name : undefined;
}

function addPath(paths: SourcePathOperation[], kind: "read" | "write" | "delete", node: SyntaxNode | undefined, context: JuliaContext, source: string): void {
  paths.push({ kind, path: staticString(node, context), source });
}

function addCommands(executions: SourceExecution[], commands: ResolvedCommand[] | undefined, source: string): void {
  if (!commands?.length) {
    executions.push({ kind: "argv", executable: undefined, args: undefined, source });
    return;
  }
  for (const command of commands) {
    executions.push({
      kind: "argv",
      executable: command.argv[0],
      args: command.argv.slice(1),
      source,
      ...(command.cwd ? { cwd: command.cwd } : {}),
      ...(command.dynamicCwd ? { dynamicCwd: true } : {}),
    });
  }
}

function openPathArgument(args: JuliaArguments, doClause: SyntaxNode | undefined, context: JuliaContext): { path?: SyntaxNode; mode?: SyntaxNode } {
  if (doClause) return { path: args.positional[0], mode: args.positional[1] };
  const first = args.positional[0];
  const second = args.positional[1];
  const third = args.positional[2];
  const secondValue = staticString(second, context);
  if (third) return { path: second, mode: third };
  if (second && /^(?:r|w|a)\+?$/.test(secondValue ?? "")) return { path: first, mode: second };
  if (staticString(first, context) !== undefined) return { path: first, mode: second };
  if (!second) return { path: first };
  return { path: second };
}

function addOpenOperation(paths: SourcePathOperation[], args: JuliaArguments, doClause: SyntaxNode | undefined, context: JuliaContext, source: string): void {
  const selected = openPathArgument(args, doClause, context);
  const mode = staticString(selected.mode, context);
  const readKeyword = booleanValue(args.keywords.get("read"));
  const mutativeKeywords = ["write", "create", "truncate", "append"].map((name) => booleanValue(args.keywords.get(name)));
  const hasDynamicKeyword = ["read", "write", "create", "truncate", "append"].some((name) => args.keywords.has(name) && booleanValue(args.keywords.get(name)) === undefined);
  const mutative = mutativeKeywords.some((value) => value === true);
  if (!selected.mode && !args.keywords.size) addPath(paths, "read", selected.path, context, source);
  else if (mode !== undefined) {
    if (/r|\+/.test(mode)) addPath(paths, "read", selected.path, context, source);
    if (/[wa+]/.test(mode)) addPath(paths, "write", selected.path, context, source);
  } else if (hasDynamicKeyword || selected.mode) {
    addPath(paths, "read", selected.path, context, source);
    addPath(paths, "write", selected.path, context, source);
  } else {
    if (readKeyword === true || !mutative) addPath(paths, "read", selected.path, context, source);
    if (mutative) addPath(paths, "write", selected.path, context, source);
  }
}

/** Parse Julia without executing Julia or source code and expose concrete Base/stdlib side effects. */
export function juliaOperations(
  source: string,
  options: { cwd?: string; sourceDirectory?: string; sourceFile?: string } = {},
): SourceScreening {
  const tree = parser.parse(source);
  if (tree.rootNode.hasError) return { paths: [], executions: [], parseError: "Julia syntax could not be parsed completely" };

  const cwd = options.cwd ?? ".";
  const context: JuliaContext = {
    cwd,
    sourceDirectory: options.sourceDirectory ?? cwd,
    ...(options.sourceFile ? { sourceFile: options.sourceFile } : {}),
    strings: new Map(),
    arrays: new Map(),
    commands: new Map(),
  };
  const assignments: Array<{ name: string; value: SyntaxNode }> = [];
  const assignmentCounts = new Map<string, number>();
  const locallyBound = new Set<string>();
  walk(tree.rootNode, (node) => {
    const assignment = assignmentParts(node);
    if (assignment.name && assignment.value) {
      assignments.push({ name: assignment.name, value: assignment.value });
      assignmentCounts.set(assignment.name, (assignmentCounts.get(assignment.name) ?? 0) + 1);
      if (RECOGNIZED_DIRECT_FUNCTIONS.has(assignment.name)) locallyBound.add(assignment.name);
    }
    if (assignment.functionName) locallyBound.add(assignment.functionName);
    const functionName = functionDefinitionName(node);
    if (functionName) locallyBound.add(functionName);
  });

  for (let pass = 0; pass < assignments.length + 1; pass++) {
    let changed = false;
    for (const assignment of assignments) {
      if (assignmentCounts.get(assignment.name) !== 1) continue;
      const value = staticString(assignment.value, context);
      if (value !== undefined && context.strings.get(assignment.name) !== value) {
        context.strings.set(assignment.name, value);
        changed = true;
      }
      const values = staticArray(assignment.value, context);
      if (values && JSON.stringify(context.arrays.get(assignment.name)) !== JSON.stringify(values)) {
        context.arrays.set(assignment.name, values);
        changed = true;
      }
      const commands = commandValues(assignment.value, context);
      if (commands && JSON.stringify(context.commands.get(assignment.name)) !== JSON.stringify(commands)) {
        context.commands.set(assignment.name, commands);
        changed = true;
      }
    }
    if (!changed) break;
  }

  const paths: SourcePathOperation[] = [];
  const executions: SourceExecution[] = [];
  walk(tree.rootNode, (node) => {
    if (paths.length + executions.length > MAX_SOURCE_OPERATIONS || node.type !== "call_expression") return;
    const { callee, args: argNode, doClause } = callParts(node);
    const fullName = expressionName(callee);
    const args = parseArguments(argNode);
    const name = builtinCall(fullName, locallyBound);
    const label = `julia:${fullName ?? "call"}`;

    if (name === "include") {
      const pathNode = args.positional.at(-1);
      executions.push({ kind: "module", path: staticString(pathNode, context), source: label, sourceRelative: true, language: "julia" });
      return;
    }
    if (name === "include_dependency") {
      addPath(paths, "read", args.positional[0], context, label);
      return;
    }
    if (fullName === "TOML.parsefile" || fullName === "Pkg.TOML.parsefile") {
      addPath(paths, "read", args.positional[0], context, label);
      return;
    }
    if (fullName === "Downloads.download" || name === "download") {
      addPath(paths, "write", args.positional[1], context, label);
      return;
    }

    if (PROCESS_FUNCTIONS.has(name ?? "")) {
      addCommands(executions, commandValues(args.positional[0], context), label);
      return;
    }
    if (PROCESS_OR_READ_FUNCTIONS.has(name ?? "") && isCommandExpression(args.positional[0], context)) {
      addCommands(executions, commandValues(args.positional[0], context), label);
      return;
    }
    if (name === "open") {
      addOpenOperation(paths, args, doClause, context, label);
      return;
    }
    if (READ_FUNCTIONS.has(name ?? "")) {
      addPath(paths, "read", args.positional[0], context, label);
      return;
    }
    if (name === "write") {
      addPath(paths, "write", args.positional[0], context, label);
      return;
    }
    if (WRITE_FUNCTIONS.has(name ?? "")) {
      addPath(paths, "write", args.positional[0], context, label);
      return;
    }
    if (DELETE_FUNCTIONS.has(name ?? "")) {
      addPath(paths, "delete", args.positional[0], context, label);
      return;
    }
    if (COPY_FUNCTIONS.has(name ?? "")) {
      addPath(paths, "read", args.positional[0], context, label);
      addPath(paths, "write", args.positional[1], context, label);
      return;
    }
    if (RENAME_FUNCTIONS.has(name ?? "")) {
      addPath(paths, "delete", args.positional[0], context, label);
      addPath(paths, "write", args.positional[1], context, label);
      return;
    }
    if (name === "symlink") {
      addPath(paths, "write", args.positional[1], context, label);
      return;
    }
    if (name === "hardlink") {
      addPath(paths, "read", args.positional[0], context, label);
      addPath(paths, "write", args.positional[1], context, label);
      return;
    }
    if (["mktemp", "mktempdir"].includes(name ?? "")) paths.push({ kind: "write", source: `${label} with runtime-generated destination` });
  });

  if (paths.length + executions.length > MAX_SOURCE_OPERATIONS) {
    return { paths: [], executions: [], parseError: `Julia source exposes more than ${MAX_SOURCE_OPERATIONS} bounded operations` };
  }
  return { paths, executions };
}
