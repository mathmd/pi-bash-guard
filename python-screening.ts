import { parser } from "@lezer/python";
import type { SyntaxNode } from "@lezer/common";
import { join } from "node:path";
import type { SourceExecution, SourcePathOperation, SourceScreening } from "./source-operations.ts";

interface PythonArguments {
  positional: SyntaxNode[];
  keywords: Map<string, SyntaxNode>;
}

interface ImportedFunction { module: string; name: string }

const MAX_SOURCE_OPERATIONS = 1_024;
const READ_FUNCTIONS = new Map<string, Set<string>>([
  ["os", new Set(["listdir", "readlink", "scandir", "stat", "lstat", "statvfs"])],
]);
const DELETE_FUNCTIONS = new Map<string, Set<string>>([
  ["os", new Set(["remove", "unlink", "rmdir", "removedirs"])],
  ["shutil", new Set(["rmtree"])],
]);
const WRITE_FUNCTIONS = new Map<string, Set<string>>([
  ["os", new Set(["mkdir", "makedirs", "chmod", "chown", "lchown", "utime", "truncate"])],
]);
const COPY_FUNCTIONS = new Map<string, Set<string>>([
  ["shutil", new Set(["copy", "copy2", "copyfile", "copytree", "copymode", "copystat"])],
]);
const RENAME_FUNCTIONS = new Map<string, Set<string>>([
  ["os", new Set(["rename", "replace", "renames"])],
  ["shutil", new Set(["move"])],
]);
const PATH_READ_METHODS = new Set(["read_text", "read_bytes", "iterdir", "readlink", "stat", "lstat"]);
const PATH_WRITE_METHODS = new Set(["write_text", "write_bytes", "touch", "mkdir", "chmod", "lchmod", "symlink_to", "hardlink_to"]);
const PATH_DELETE_METHODS = new Set(["unlink", "rmdir"]);
const PATH_RENAME_METHODS = new Set(["rename", "replace"]);
const SUBPROCESS_FUNCTIONS = new Set(["run", "Popen", "call", "check_call", "check_output"]);
const SUBPROCESS_SHELL_FUNCTIONS = new Set(["getoutput", "getstatusoutput"]);

function children(node: SyntaxNode): SyntaxNode[] {
  const result: SyntaxNode[] = [];
  for (let child = node.firstChild; child; child = child.nextSibling) result.push(child);
  return result;
}

function descendants(node: SyntaxNode, visit: (node: SyntaxNode) => void): void {
  visit(node);
  for (let child = node.firstChild; child; child = child.nextSibling) descendants(child, visit);
}

function textOf(node: SyntaxNode, source: string): string {
  return source.slice(node.from, node.to);
}

function decodePythonString(raw: string): string | undefined {
  const prefix = raw.match(/^[rRuUbBfF]*/)?.[0] ?? "";
  if (/f/i.test(prefix)) return undefined;
  const quoted = raw.slice(prefix.length);
  const quote = quoted.startsWith("'''") ? "'''" : quoted.startsWith('"""') ? '"""' : quoted[0];
  if (!quote || !["'", '"', "'''", '"""'].includes(quote) || !quoted.endsWith(quote)) return undefined;
  const body = quoted.slice(quote.length, -quote.length);
  if (/r/i.test(prefix)) return body;
  let value = "";
  for (let index = 0; index < body.length; index++) {
    const character = body[index]!;
    if (character !== "\\") { value += character; continue; }
    const escaped = body[++index];
    if (escaped === undefined) return undefined;
    const simple: Record<string, string> = { n: "\n", r: "\r", t: "\t", b: "\b", f: "\f", v: "\v", a: "\x07", "\\": "\\", "'": "'", '"': '"', "\n": "" };
    if (escaped in simple) { value += simple[escaped]; continue; }
    const width = escaped === "x" ? 2 : escaped === "u" ? 4 : escaped === "U" ? 8 : 0;
    if (width) {
      const digits = body.slice(index + 1, index + 1 + width);
      if (!new RegExp(`^[0-9a-fA-F]{${width}}$`).test(digits)) return undefined;
      value += String.fromCodePoint(Number.parseInt(digits, 16));
      index += width;
      continue;
    }
    if (/[0-7]/.test(escaped)) {
      const rest = body.slice(index, index + 3).match(/^[0-7]{1,3}/)?.[0] ?? escaped;
      value += String.fromCodePoint(Number.parseInt(rest, 8));
      index += rest.length - 1;
      continue;
    }
    // Python preserves unknown escapes in ordinary strings.
    value += `\\${escaped}`;
  }
  return value;
}

function callParts(node: SyntaxNode): { callee?: SyntaxNode; args?: SyntaxNode } {
  if (node.name !== "CallExpression") return {};
  const direct = children(node);
  return { callee: direct[0], args: direct.find((child) => child.name === "ArgList") };
}

function parseArguments(node: SyntaxNode | undefined, source: string): PythonArguments {
  const positional: SyntaxNode[] = [];
  const keywords = new Map<string, SyntaxNode>();
  if (!node) return { positional, keywords };
  const direct = children(node);
  for (let index = 0; index < direct.length; index++) {
    const child = direct[index]!;
    if (["(", ")", ","].includes(child.name)) continue;
    if (child.name === "VariableName" && direct[index + 1]?.name === "AssignOp" && textOf(direct[index + 1]!, source) === "=") {
      const value = direct[index + 2];
      if (value) keywords.set(textOf(child, source), value);
      index += 2;
      continue;
    }
    positional.push(child);
  }
  return { positional, keywords };
}

function memberName(node: SyntaxNode | undefined, source: string): { root?: string; properties: string[] } {
  if (!node) return { properties: [] };
  if (node.name === "VariableName") return { root: textOf(node, source), properties: [] };
  if (node.name !== "MemberExpression") return { properties: [] };
  const direct = children(node);
  const parent = memberName(direct[0], source);
  const property = direct.findLast((child) => child.name === "PropertyName");
  return property ? { ...parent, properties: [...parent.properties, textOf(property, source)] } : { properties: [] };
}

function booleanValue(node: SyntaxNode | undefined, source: string): boolean | undefined {
  if (!node) return undefined;
  if (node.name === "Boolean") return textOf(node, source) === "True";
  if (node.name === "None" || (node.name === "VariableName" && textOf(node, source) === "None")) return false;
  return undefined;
}

function staticString(
  node: SyntaxNode | undefined,
  source: string,
  strings: Map<string, string>,
  arrays: Map<string, Array<string | undefined>>,
  pathNames: Set<string>,
  pathConstructors: Set<string>,
  namespaces: Map<string, string>,
  importedFunctions: Map<string, ImportedFunction>,
  depth = 0,
): string | undefined {
  if (!node || depth > 16) return undefined;
  if (node.name === "String") return decodePythonString(textOf(node, source));
  if (node.name === "ContinuedString") {
    const values = children(node).filter((child) => child.name === "String").map((child) => staticString(child, source, strings, arrays, pathNames, pathConstructors, namespaces, importedFunctions, depth + 1));
    return values.every((value) => value !== undefined) ? values.join("") : undefined;
  }
  if (node.name === "VariableName") return strings.get(textOf(node, source));
  if (node.name === "ParenthesizedExpression") {
    return staticString(children(node).find((child) => !["(", ")"].includes(child.name)), source, strings, arrays, pathNames, pathConstructors, namespaces, importedFunctions, depth + 1);
  }
  if (node.name === "BinaryExpression") {
    const direct = children(node);
    const operator = direct.find((child) => ["ArithOp", "BitOp"].includes(child.name));
    const operands = direct.filter((child) => child !== operator);
    const left = staticString(operands[0], source, strings, arrays, pathNames, pathConstructors, namespaces, importedFunctions, depth + 1);
    const right = staticString(operands[1], source, strings, arrays, pathNames, pathConstructors, namespaces, importedFunctions, depth + 1);
    if (left === undefined || right === undefined || !operator) return undefined;
    const symbol = textOf(operator, source);
    if (symbol === "+") return left + right;
    if (symbol === "/") return join(left, right);
    return undefined;
  }
  if (node.name === "CallExpression") {
    const { callee, args: argNode } = callParts(node);
    const call = memberName(callee, source);
    const args = parseArguments(argNode, source);
    const directName = call.root && !call.properties.length ? call.root : undefined;
    const module = call.root ? namespaces.get(call.root) : undefined;
    if ((directName && pathConstructors.has(directName)) || (module === "pathlib" && call.properties.length === 1 && ["Path", "PurePath"].includes(call.properties[0]!))) {
      return staticString(args.positional[0], source, strings, arrays, pathNames, pathConstructors, namespaces, importedFunctions, depth + 1);
    }
    const imported = directName ? importedFunctions.get(directName) : undefined;
    const osPathJoin = (module === "os" && call.properties.join(".") === "path.join") || (imported?.module === "os.path" && imported.name === "join");
    if (osPathJoin) {
      const values = args.positional.map((argument) => staticString(argument, source, strings, arrays, pathNames, pathConstructors, namespaces, importedFunctions, depth + 1));
      return values.length && values.every((value) => value !== undefined) ? join(...values as string[]) : undefined;
    }
  }
  return undefined;
}

function staticArray(
  node: SyntaxNode | undefined,
  source: string,
  strings: Map<string, string>,
  arrays: Map<string, Array<string | undefined>>,
  pathNames: Set<string>,
  pathConstructors: Set<string>,
  namespaces: Map<string, string>,
  importedFunctions: Map<string, ImportedFunction>,
): Array<string | undefined> | undefined {
  if (!node) return undefined;
  if (node.name === "VariableName") return arrays.get(textOf(node, source));
  if (!["ArrayExpression", "TupleExpression"].includes(node.name)) return undefined;
  return children(node)
    .filter((child) => !["[", "]", "(", ")", ","].includes(child.name))
    .map((child) => staticString(child, source, strings, arrays, pathNames, pathConstructors, namespaces, importedFunctions));
}

function isPathExpression(node: SyntaxNode | undefined, source: string, pathNames: Set<string>, pathConstructors: Set<string>, namespaces: Map<string, string>): boolean {
  if (!node) return false;
  if (node.name === "VariableName") return pathNames.has(textOf(node, source));
  if (node.name === "BinaryExpression") return children(node).some((child) => child.name === "ArithOp" && textOf(child, source) === "/");
  if (node.name !== "CallExpression") return false;
  const { callee } = callParts(node);
  const call = memberName(callee, source);
  return Boolean((call.root && !call.properties.length && pathConstructors.has(call.root)) ||
    (call.root && namespaces.get(call.root) === "pathlib" && call.properties.length === 1 && ["Path", "PurePath"].includes(call.properties[0]!)));
}

function importedCall(node: SyntaxNode, source: string, namespaces: Map<string, string>, functions: Map<string, ImportedFunction>): ImportedFunction | undefined {
  const { callee } = callParts(node);
  const call = memberName(callee, source);
  if (!call.root) return undefined;
  if (!call.properties.length) return functions.get(call.root);
  const module = namespaces.get(call.root);
  return module && call.properties.length === 1 ? { module, name: call.properties[0]! } : undefined;
}

function pythonModulePath(module: string): string {
  const relativeDots = module.match(/^\.+/)?.[0].length ?? 0;
  const name = module.slice(relativeDots).replaceAll(".", "/");
  return `${"../".repeat(Math.max(0, relativeDots - 1))}${name || "."}`;
}

function addPath(paths: SourcePathOperation[], kind: "read" | "write" | "delete", path: string | undefined, source: string): void {
  paths.push({ kind, path, source });
}

/** Parse Python without executing it and expose concrete stdlib side effects. */
export function pythonOperations(source: string): SourceScreening {
  const tree = parser.parse(source);
  let syntaxError = false;
  descendants(tree.topNode, (node) => { if (node.type.isError) syntaxError = true; });
  if (syntaxError) return { paths: [], executions: [], parseError: "Python syntax could not be parsed completely" };

  const namespaces = new Map<string, string>();
  const importedFunctions = new Map<string, ImportedFunction>();
  const pathConstructors = new Set<string>();
  const strings = new Map<string, string>();
  const arrays = new Map<string, Array<string | undefined>>();
  const pathNames = new Set<string>();
  const assignments: SyntaxNode[] = [];
  const moduleImports = new Set<string>();
  const locallyBound = new Set<string>();

  descendants(tree.topNode, (node) => {
    if (node.name === "ImportStatement") {
      const statement = textOf(node, source).replace(/\s+/g, " ").trim();
      const from = statement.match(/^from\s+([.]*[A-Za-z_][\w.]*|[.]+)\s+import\s+(.+)$/);
      if (from) {
        if (!/^\.+$/.test(from[1]!)) moduleImports.add(pythonModulePath(from[1]!));
        for (const item of from[2]!.replace(/[()]/g, "").split(",")) {
          const match = item.trim().match(/^([A-Za-z_][\w]*)(?:\s+as\s+([A-Za-z_][\w]*))?$/);
          if (!match) continue;
          const imported = match[1]!;
          const local = match[2] ?? imported;
          if (/^\.+$/.test(from[1]!)) moduleImports.add(join(pythonModulePath(from[1]!), imported));
          importedFunctions.set(local, { module: from[1]!, name: imported });
          if (from[1] === "pathlib" && ["Path", "PurePath"].includes(imported)) pathConstructors.add(local);
        }
      } else {
        const plain = statement.match(/^import\s+(.+)$/);
        if (plain) for (const item of plain[1]!.split(",")) {
          const match = item.trim().match(/^([A-Za-z_][\w.]*)(?:\s+as\s+([A-Za-z_][\w]*))?$/);
          if (!match) continue;
          moduleImports.add(pythonModulePath(match[1]!));
          namespaces.set(match[2] ?? match[1]!.split(".")[0]!, match[1]!);
        }
      }
    } else if (node.name === "AssignStatement") {
      assignments.push(node);
      const target = children(node)[0];
      if (target?.name === "VariableName") locallyBound.add(textOf(target, source));
    } else if (["FunctionDefinition", "ClassDefinition"].includes(node.name)) {
      const name = children(node).find((child) => child.name === "VariableName");
      if (name) locallyBound.add(textOf(name, source));
      const params = children(node).find((child) => child.name === "ParamList");
      if (params) descendants(params, (child) => { if (child.name === "VariableName") locallyBound.add(textOf(child, source)); });
    }
  });
  for (const name of locallyBound) {
    namespaces.delete(name);
    importedFunctions.delete(name);
    pathConstructors.delete(name);
  }


  for (let pass = 0; pass < assignments.length + 1; pass++) {
    let changed = false;
    for (const assignment of assignments) {
      const direct = children(assignment);
      const nameNode = direct[0];
      const valueNode = direct.at(-1);
      if (!nameNode || nameNode.name !== "VariableName" || !valueNode || valueNode === nameNode) continue;
      const name = textOf(nameNode, source);
      const value = staticString(valueNode, source, strings, arrays, pathNames, pathConstructors, namespaces, importedFunctions);
      if (value !== undefined && strings.get(name) !== value) { strings.set(name, value); changed = true; }
      const values = staticArray(valueNode, source, strings, arrays, pathNames, pathConstructors, namespaces, importedFunctions);
      if (values && JSON.stringify(arrays.get(name)) !== JSON.stringify(values)) { arrays.set(name, values); changed = true; }
      if (isPathExpression(valueNode, source, pathNames, pathConstructors, namespaces) && !pathNames.has(name)) { pathNames.add(name); changed = true; }
    }
    if (!changed) break;
  }

  const paths: SourcePathOperation[] = [];
  const executions: SourceExecution[] = [];
  for (const path of moduleImports) {
    executions.push({ kind: "module", path, source: "python static import", sourceRelative: true, language: "python" });
  }
  descendants(tree.topNode, (node) => {
    if (paths.length + executions.length > MAX_SOURCE_OPERATIONS || node.name !== "CallExpression") return;
    const { callee, args: argNode } = callParts(node);
    const args = parseArguments(argNode, source);
    const call = importedCall(node, source, namespaces, importedFunctions);
    const chain = memberName(callee, source);
    const receiver = callee?.name === "MemberExpression" ? children(callee)[0] : undefined;
    const method = chain.properties.at(-1);
    const label = call ? `python:${call.module}.${call.name}` : method ? `python:pathlib.${method}` : `python:${chain.root ?? "call"}`;
    const value = (argument: SyntaxNode | undefined): string | undefined => staticString(argument, source, strings, arrays, pathNames, pathConstructors, namespaces, importedFunctions);

    if (call && READ_FUNCTIONS.get(call.module)?.has(call.name)) addPath(paths, "read", value(args.positional[0]), label);
    else if (call && DELETE_FUNCTIONS.get(call.module)?.has(call.name)) addPath(paths, "delete", value(args.positional[0]), label);
    else if (call && WRITE_FUNCTIONS.get(call.module)?.has(call.name)) addPath(paths, "write", value(args.positional[0]), label);
    else if (call && COPY_FUNCTIONS.get(call.module)?.has(call.name)) {
      addPath(paths, "read", value(args.positional[0]), label);
      addPath(paths, "write", value(args.positional[1]), label);
    } else if (call && RENAME_FUNCTIONS.get(call.module)?.has(call.name)) {
      addPath(paths, "delete", value(args.positional[0]), label);
      addPath(paths, "write", value(args.positional[1]), label);
    } else if (call?.module === "os" && call.name === "open") {
      // os.open uses bitmask flags. Anything except a literal O_RDONLY is conservatively treated as potentially mutative.
      const flags = args.positional[1];
      const flagChain = memberName(flags, source);
      if (flagChain.root && namespaces.get(flagChain.root) === "os" && flagChain.properties.join(".") === "O_RDONLY") {
        addPath(paths, "read", value(args.positional[0]), label);
      } else {
        addPath(paths, "read", value(args.positional[0]), label);
        paths.push({ kind: "write", source: `${label} with mutative or unresolved flags` });
      }
    }

    const directName = chain.root && !chain.properties.length ? chain.root : undefined;
    const builtinOpen = directName === "open" && !locallyBound.has("open") && !importedFunctions.has("open");
    const pathReceiver = method && isPathExpression(receiver, source, pathNames, pathConstructors, namespaces);
    const openTarget = pathReceiver ? receiver : args.positional[0];
    if ((builtinOpen || (pathReceiver && method === "open")) && openTarget?.name !== "Number") {
      const modeNode = args.keywords.get("mode") ?? args.positional[pathReceiver ? 0 : 1];
      const mode = value(modeNode);
      const path = value(openTarget);
      if (!modeNode) addPath(paths, "read", path, label);
      else if (mode === undefined) {
        addPath(paths, "read", path, label);
        paths.push({ kind: "write", source: `${label} with dynamic mode` });
      } else {
        if (/r|\+/.test(mode)) addPath(paths, "read", path, label);
        if (/[wax+]/.test(mode)) addPath(paths, "write", path, label);
      }
    } else if (pathReceiver && method && PATH_READ_METHODS.has(method)) addPath(paths, "read", value(receiver), label);
    else if (pathReceiver && method === "hardlink_to") {
      addPath(paths, "read", value(args.positional[0]), label);
      addPath(paths, "write", value(receiver), label);
    } else if (pathReceiver && method && PATH_WRITE_METHODS.has(method)) addPath(paths, "write", value(receiver), label);
    else if (pathReceiver && method && PATH_DELETE_METHODS.has(method)) addPath(paths, "delete", value(receiver), label);
    else if (pathReceiver && method && PATH_RENAME_METHODS.has(method)) {
      addPath(paths, "delete", value(receiver), label);
      addPath(paths, "write", value(args.positional[0]), label);
    }

    const dynamicImport = (directName === "__import__" && !locallyBound.has("__import__")) || (call?.module === "importlib" && call.name === "import_module");
    if (dynamicImport) {
      const module = value(args.positional[0]);
      executions.push({
        kind: "module",
        path: module === undefined ? undefined : pythonModulePath(module),
        source: "python dynamic import",
        sourceRelative: true,
        language: "python",
      });
      return;
    }
    if (!call) return;
    if (call.module === "os" && ["system", "popen"].includes(call.name)) {
      executions.push({ kind: "shell", command: value(args.positional[0]), source: label });
      return;
    }
    if (call.module === "subprocess" && SUBPROCESS_SHELL_FUNCTIONS.has(call.name)) {
      executions.push({ kind: "shell", command: value(args.positional[0]), source: label });
      return;
    }
    if (call.module === "subprocess" && SUBPROCESS_FUNCTIONS.has(call.name)) {
      const commandNode = args.positional[0] ?? args.keywords.get("args");
      const command = value(commandNode);
      const argv = staticArray(commandNode, source, strings, arrays, pathNames, pathConstructors, namespaces, importedFunctions);
      const shellNode = args.keywords.get("shell");
      const resolvedShell = booleanValue(shellNode, source);
      if (shellNode && resolvedShell === undefined) {
        executions.push({ kind: "shell", source: `${label} with dynamic shell mode` });
        return;
      }
      const shell = resolvedShell ?? false;
      const cwdNode = args.keywords.get("cwd");
      const cwd = value(cwdNode);
      const location = cwd ? { cwd } : cwdNode ? { dynamicCwd: true as const } : {};
      if (shell) executions.push({ kind: "shell", command, source: label, ...location });
      else if (argv) executions.push({ kind: "argv", executable: argv[0], args: argv.slice(1), source: label, ...location });
      else executions.push({ kind: "argv", executable: command, args: command === undefined ? undefined : [], source: label, ...location });
      return;
    }
    if (call.module === "os" && /^exec[lv]pe?$/.test(call.name)) {
      const vector = call.name.includes("v");
      executions.push({
        kind: "argv",
        executable: value(args.positional[0]),
        args: vector
          ? staticArray(args.positional[1], source, strings, arrays, pathNames, pathConstructors, namespaces, importedFunctions)
          : args.positional.slice(1).map(value),
        source: label,
      });
    }
  });

  if (paths.length + executions.length > MAX_SOURCE_OPERATIONS) {
    return { paths: [], executions: [], parseError: `Python source exposes more than ${MAX_SOURCE_OPERATIONS} bounded operations` };
  }
  return { paths, executions };
}
