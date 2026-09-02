import { parse } from "@babel/parser";
import type { SourceExecution, SourcePathOperation, SourceScreening } from "./source-operations.ts";

interface AstNode {
  type: string;
  [key: string]: unknown;
}

const MAX_SOURCE_OPERATIONS = 1_024;
type ChildProcessSink = "shell" | "argv" | "module";
type ModuleKind = "child_process" | "fs" | "fs/promises";
type Sink =
  | { family: "child_process"; kind: ChildProcessSink; name: string }
  | { family: "fs"; kind: "read" | "write" | "delete" | "copy" | "symlink" | "rename" | "open" | "mkdtemp"; name: string };

export type JavaScriptExecution = SourceExecution;
export interface JavaScriptScreening extends SourceScreening {}

function isNode(value: unknown): value is AstNode {
  return typeof value === "object" && value !== null && typeof (value as { type?: unknown }).type === "string";
}

function walk(node: AstNode, visit: (node: AstNode) => void): void {
  visit(node);
  for (const [key, value] of Object.entries(node)) {
    if (["loc", "start", "end", "extra", "comments", "errors"].includes(key)) continue;
    if (isNode(value)) walk(value, visit);
    else if (Array.isArray(value)) for (const item of value) if (isNode(item)) walk(item, visit);
  }
}

function identifierName(node: unknown): string | undefined {
  return isNode(node) && node.type === "Identifier" && typeof node.name === "string" ? node.name : undefined;
}

function propertyName(node: unknown): string | undefined {
  if (!isNode(node)) return undefined;
  if (node.type === "Identifier" && typeof node.name === "string") return node.name;
  if (node.type === "StringLiteral" && typeof node.value === "string") return node.value;
  return undefined;
}

function unwrap(node: unknown): unknown {
  while (isNode(node) && [
    "TSAsExpression", "TSSatisfiesExpression", "TSTypeAssertion", "TSNonNullExpression",
    "TypeCastExpression", "ParenthesizedExpression", "AwaitExpression",
  ].includes(node.type)) node = node.expression;
  return node;
}

function stringValue(node: unknown, strings: Map<string, string>, depth = 0): string | undefined {
  if (depth > 16) return undefined;
  node = unwrap(node);
  if (!isNode(node)) return undefined;
  if (node.type === "StringLiteral" && typeof node.value === "string") return node.value;
  if (node.type === "NumericLiteral" && typeof node.value === "number") return String(node.value);
  if (node.type === "Identifier" && typeof node.name === "string") return strings.get(node.name);
  if (node.type === "BinaryExpression" && node.operator === "+") {
    const left = stringValue(node.left, strings, depth + 1);
    const right = stringValue(node.right, strings, depth + 1);
    return left !== undefined && right !== undefined ? left + right : undefined;
  }
  if (node.type === "TemplateLiteral" && Array.isArray(node.quasis) && Array.isArray(node.expressions)) {
    let value = "";
    for (let index = 0; index < node.quasis.length; index++) {
      const quasi = node.quasis[index];
      if (!isNode(quasi) || typeof quasi.value !== "object" || quasi.value === null ||
        typeof (quasi.value as { cooked?: unknown }).cooked !== "string") return undefined;
      value += (quasi.value as { cooked: string }).cooked;
      if (index < node.expressions.length) {
        const expression = stringValue(node.expressions[index], strings, depth + 1);
        if (expression === undefined) return undefined;
        value += expression;
      }
    }
    return value;
  }
  return undefined;
}

function arrayValue(node: unknown, strings: Map<string, string>, arrays: Map<string, Array<string | undefined>>): Array<string | undefined> | undefined {
  node = unwrap(node);
  if (!isNode(node)) return undefined;
  if (node.type === "Identifier" && typeof node.name === "string") return arrays.get(node.name);
  if (node.type !== "ArrayExpression" || !Array.isArray(node.elements)) return undefined;
  return node.elements.map((element) => stringValue(element, strings));
}

function callArguments(node: AstNode): unknown[] {
  return Array.isArray(node.arguments) ? node.arguments : [];
}

function requiredModule(node: unknown, strings: Map<string, string>): string | undefined {
  node = unwrap(node);
  if (!isNode(node) || node.type !== "CallExpression" || identifierName(node.callee) !== "require") return undefined;
  return stringValue(callArguments(node)[0], strings);
}

function moduleKind(value: string | undefined): ModuleKind | undefined {
  if (value === "child_process" || value === "node:child_process") return "child_process";
  if (value === "fs" || value === "node:fs") return "fs";
  if (value === "fs/promises" || value === "node:fs/promises") return "fs/promises";
  return undefined;
}

const CHILD_PROCESS_SINKS = new Map<string, ChildProcessSink>([
  ["exec", "shell"], ["execSync", "shell"],
  ["execFile", "argv"], ["execFileSync", "argv"],
  ["spawn", "argv"], ["spawnSync", "argv"],
  ["fork", "module"],
]);

const FS_READ_FIRST = new Set([
  "access", "accessSync", "existsSync", "lstat", "lstatSync", "opendir", "opendirSync", "readFile", "readFileSync",
  "readdir", "readdirSync", "readlink", "readlinkSync", "realpath", "realpathSync", "stat", "statSync", "statfs", "statfsSync",
  "createReadStream",
]);
const FS_WRITE_FIRST = new Set([
  "appendFile", "appendFileSync", "writeFile", "writeFileSync", "truncate", "truncateSync",
  "chmod", "chmodSync", "chown", "chownSync", "lchmod", "lchmodSync", "lchown", "lchownSync",
  "lutimes", "lutimesSync", "utimes", "utimesSync", "mkdir", "mkdirSync", "createWriteStream",
]);
const FS_DELETE_FIRST = new Set(["rm", "rmSync", "rmdir", "rmdirSync", "unlink", "unlinkSync"]);
const FS_COPY = new Set(["copyFile", "copyFileSync", "cp", "cpSync", "link", "linkSync"]);
const FS_SYMLINK = new Set(["symlink", "symlinkSync"]);
const FS_RENAME = new Set(["rename", "renameSync"]);
const FS_OPEN = new Set(["open", "openSync"]);
const FS_MKDTEMP = new Set(["mkdtemp", "mkdtempSync"]);

function sinkFor(module: ModuleKind, name: string): Sink | undefined {
  if (module === "child_process") {
    const kind = CHILD_PROCESS_SINKS.get(name);
    return kind ? { family: "child_process", kind, name } : undefined;
  }
  if (FS_READ_FIRST.has(name)) return { family: "fs", kind: "read", name };
  if (FS_WRITE_FIRST.has(name)) return { family: "fs", kind: "write", name };
  if (FS_DELETE_FIRST.has(name)) return { family: "fs", kind: "delete", name };
  if (FS_COPY.has(name)) return { family: "fs", kind: "copy", name };
  if (FS_SYMLINK.has(name)) return { family: "fs", kind: "symlink", name };
  if (FS_RENAME.has(name)) return { family: "fs", kind: "rename", name };
  if (FS_OPEN.has(name)) return { family: "fs", kind: "open", name };
  if (FS_MKDTEMP.has(name)) return { family: "fs", kind: "mkdtemp", name };
  return undefined;
}

function bindingNames(pattern: unknown): string[] {
  pattern = unwrap(pattern);
  if (!isNode(pattern)) return [];
  const direct = identifierName(pattern);
  if (direct) return [direct];
  if (["ObjectPattern", "ArrayPattern"].includes(pattern.type)) {
    const values = pattern.type === "ObjectPattern" ? pattern.properties : pattern.elements;
    if (!Array.isArray(values)) return [];
    return values.flatMap((value) => {
      if (!isNode(value)) return [];
      if (value.type === "ObjectProperty") return bindingNames(value.value);
      if (value.type === "RestElement") return bindingNames(value.argument);
      return bindingNames(value);
    });
  }
  if (pattern.type === "AssignmentPattern") return bindingNames(pattern.left);
  if (pattern.type === "RestElement") return bindingNames(pattern.argument);
  return [];
}

function memberChain(node: unknown, strings: Map<string, string>): { root?: string; required?: ModuleKind; properties: string[] } {
  node = unwrap(node);
  if (!isNode(node)) return { properties: [] };
  const direct = identifierName(node);
  if (direct) return { root: direct, properties: [] };
  const required = moduleKind(requiredModule(node, strings));
  if (required) return { required, properties: [] };
  if (!["MemberExpression", "OptionalMemberExpression"].includes(node.type)) return { properties: [] };
  const parent = memberChain(node.object, strings);
  const property = propertyName(node.property);
  return property ? { ...parent, properties: [...parent.properties, property] } : { properties: [] };
}

function namespaceFromExpression(node: unknown, strings: Map<string, string>, namespaces: Map<string, ModuleKind>): ModuleKind | undefined {
  const required = moduleKind(requiredModule(node, strings));
  if (required) return required;
  const chain = memberChain(node, strings);
  const base = chain.required ?? (chain.root ? namespaces.get(chain.root) : undefined);
  if (base === "fs" && chain.properties.join(".") === "promises") return "fs/promises";
  return chain.properties.length ? undefined : base;
}

function sinkFromExpression(node: unknown, strings: Map<string, string>, namespaces: Map<string, ModuleKind>, functions: Map<string, Sink>): Sink | undefined {
  node = unwrap(node);
  const direct = identifierName(node);
  if (direct) return functions.get(direct);
  const chain = memberChain(node, strings);
  let module = chain.required ?? (chain.root ? namespaces.get(chain.root) : undefined);
  const properties = [...chain.properties];
  if (module === "fs" && properties[0] === "promises") { module = "fs/promises"; properties.shift(); }
  return module && properties.length === 1 ? sinkFor(module, properties[0]!) : undefined;
}

function isLocalModule(value: string): boolean {
  return value.startsWith("./") || value.startsWith("../") || value.startsWith("/") || value.startsWith("file:");
}

function addPath(paths: SourcePathOperation[], kind: "read" | "write" | "delete", node: unknown, strings: Map<string, string>, source: string): void {
  const value = unwrap(node);
  if (isNode(value) && value.type === "NumericLiteral") return;
  paths.push({ kind, path: stringValue(node, strings), source });
}

/** Parse JavaScript/TypeScript without executing it and expose concrete built-in side effects. */
export function javascriptExecutions(source: string): JavaScriptScreening {
  let root: AstNode;
  try {
    root = parse(source, {
      sourceType: "unambiguous",
      allowAwaitOutsideFunction: true,
      errorRecovery: false,
      plugins: ["typescript", "jsx", "decorators-legacy", "importAttributes", "explicitResourceManagement"],
    }) as unknown as AstNode;
  } catch (error) {
    return { paths: [], executions: [], parseError: error instanceof Error ? error.message : String(error) };
  }

  const declarationCounts = new Map<string, number>();
  const declarations: AstNode[] = [];
  const imports: AstNode[] = [];
  walk(root, (node) => {
    if (node.type === "ImportDeclaration") {
      imports.push(node);
      if (Array.isArray(node.specifiers)) for (const specifier of node.specifiers) {
        if (!isNode(specifier)) continue;
        for (const name of bindingNames(specifier.local)) declarationCounts.set(name, (declarationCounts.get(name) ?? 0) + 1);
      }
    }
    if (node.type === "VariableDeclaration" && Array.isArray(node.declarations)) {
      for (const declaration of node.declarations) {
        if (!isNode(declaration)) continue;
        declarations.push(declaration);
        for (const name of bindingNames(declaration.id)) declarationCounts.set(name, (declarationCounts.get(name) ?? 0) + 1);
      }
    }
    if (["FunctionDeclaration", "ClassDeclaration"].includes(node.type)) {
      for (const name of bindingNames(node.id)) declarationCounts.set(name, (declarationCounts.get(name) ?? 0) + 1);
    }
    if (["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"].includes(node.type) && Array.isArray(node.params)) {
      for (const parameter of node.params) for (const name of bindingNames(parameter)) declarationCounts.set(name, (declarationCounts.get(name) ?? 0) + 1);
    }
    if (node.type === "CatchClause") for (const name of bindingNames(node.param)) declarationCounts.set(name, (declarationCounts.get(name) ?? 0) + 1);
  });
  const unique = (name: string): boolean => declarationCounts.get(name) === 1;

  const strings = new Map<string, string>();
  const arrays = new Map<string, Array<string | undefined>>();
  const functions = new Map<string, Sink>();
  const namespaces = new Map<string, ModuleKind>();

  for (const declaration of imports) {
    const importedModule = isNode(declaration.source) && typeof declaration.source.value === "string" ? moduleKind(declaration.source.value) : undefined;
    if (!importedModule || !Array.isArray(declaration.specifiers)) continue;
    for (const specifier of declaration.specifiers) {
      if (!isNode(specifier)) continue;
      const local = identifierName(specifier.local);
      if (!local || !unique(local)) continue;
      if (specifier.type === "ImportNamespaceSpecifier" || specifier.type === "ImportDefaultSpecifier") namespaces.set(local, importedModule);
      else {
        const imported = propertyName(specifier.imported) ?? "";
        const sink = sinkFor(importedModule, imported);
        if (sink) functions.set(local, sink);
      }
    }
  }

  for (let pass = 0; pass < declarations.length + 1; pass++) {
    let changed = false;
    for (const declaration of declarations) {
      const local = identifierName(declaration.id);
      if (local && unique(local)) {
        const value = stringValue(declaration.init, strings);
        if (value !== undefined && strings.get(local) !== value) { strings.set(local, value); changed = true; }
        const values = arrayValue(declaration.init, strings, arrays);
        if (values && JSON.stringify(arrays.get(local)) !== JSON.stringify(values)) { arrays.set(local, values); changed = true; }
        const namespace = namespaceFromExpression(declaration.init, strings, namespaces);
        if (namespace && namespaces.get(local) !== namespace) { namespaces.set(local, namespace); changed = true; }
        const sink = sinkFromExpression(declaration.init, strings, namespaces, functions);
        if (sink && functions.get(local) !== sink) { functions.set(local, sink); changed = true; }
      } else if (isNode(declaration.id) && declaration.id.type === "ObjectPattern" && Array.isArray(declaration.id.properties)) {
        const namespace = namespaceFromExpression(declaration.init, strings, namespaces);
        if (!namespace) continue;
        for (const property of declaration.id.properties) {
          if (!isNode(property) || property.type !== "ObjectProperty") continue;
          const alias = identifierName(property.value);
          if (!alias || !unique(alias)) continue;
          const imported = propertyName(property.key) ?? "";
          if (namespace === "fs" && imported === "promises") {
            if (namespaces.get(alias) !== "fs/promises") { namespaces.set(alias, "fs/promises"); changed = true; }
            continue;
          }
          const sink = sinkFor(namespace, imported);
          if (sink && functions.get(alias) !== sink) { functions.set(alias, sink); changed = true; }
        }
      }
    }
    if (!changed) break;
  }

  const paths: SourcePathOperation[] = [];
  const executions: SourceExecution[] = [];
  walk(root, (node) => {
    if (paths.length + executions.length > MAX_SOURCE_OPERATIONS) return;
    const runtimeImport = !Array.isArray(node.specifiers) || node.specifiers.length === 0 ||
      node.specifiers.some((specifier) => isNode(specifier) && specifier.importKind !== "type");
    if (["ImportDeclaration", "ExportAllDeclaration", "ExportNamedDeclaration"].includes(node.type) &&
      node.importKind !== "type" && runtimeImport && isNode(node.source) && typeof node.source.value === "string" && isLocalModule(node.source.value)) {
      executions.push({ kind: "module", path: node.source.value, source: "javascript static import", sourceRelative: true, language: "javascript" });
      return;
    }
    if (node.type === "ImportExpression") {
      executions.push({ kind: "module", path: stringValue(node.source, strings), source: "javascript dynamic import", sourceRelative: true, language: "javascript" });
      return;
    }
    if (node.type !== "CallExpression" && node.type !== "OptionalCallExpression") return;
    const directCallee = unwrap(node.callee);
    if (isNode(directCallee) && directCallee.type === "Import") {
      executions.push({ kind: "module", path: stringValue(callArguments(node)[0], strings), source: "javascript dynamic import", sourceRelative: true, language: "javascript" });
      return;
    }
    if (identifierName(directCallee) === "require" && (declarationCounts.get("require") ?? 0) === 0) {
      const required = stringValue(callArguments(node)[0], strings);
      if (required === undefined || isLocalModule(required)) {
        executions.push({ kind: "module", path: required, source: "CommonJS require", sourceRelative: true, language: "javascript" });
      }
      return;
    }
    const sink = sinkFromExpression(node.callee, strings, namespaces, functions);
    if (!sink) return;
    const args = callArguments(node);
    if (sink.family === "child_process") {
      const first = stringValue(args[0], strings);
      const label = `node:child_process.${sink.name}`;
      if (sink.kind === "shell") executions.push({ kind: "shell", command: first, source: label });
      else if (sink.kind === "module") executions.push({ kind: "module", path: first, source: label, language: "javascript" });
      else executions.push({ kind: "argv", executable: first, args: arrayValue(args[1], strings, arrays), source: label });
      return;
    }

    const label = `node:fs.${sink.name}`;
    if (sink.kind === "read") addPath(paths, "read", args[0], strings, label);
    else if (sink.kind === "write") addPath(paths, "write", args[0], strings, label);
    else if (sink.kind === "delete") addPath(paths, "delete", args[0], strings, label);
    else if (sink.kind === "copy") {
      addPath(paths, "read", args[0], strings, label);
      addPath(paths, "write", args[1], strings, label);
    } else if (sink.kind === "symlink") {
      addPath(paths, "write", args[1], strings, label);
    } else if (sink.kind === "rename") {
      addPath(paths, "delete", args[0], strings, label);
      addPath(paths, "write", args[1], strings, label);
    } else if (sink.kind === "open") {
      const flags = stringValue(args[1], strings);
      if (flags === undefined) {
        addPath(paths, "read", args[0], strings, label);
        paths.push({ kind: "write", source: `${label} with dynamic flags` });
      } else {
        if (/r|\+/.test(flags)) addPath(paths, "read", args[0], strings, label);
        if (/[wax+]/.test(flags)) addPath(paths, "write", args[0], strings, label);
      }
    } else if (sink.kind === "mkdtemp") {
      paths.push({ kind: "write", source: `${label} with runtime-generated destination` });
    }
  });

  if (paths.length + executions.length > MAX_SOURCE_OPERATIONS) {
    return { paths: [], executions: [], parseError: `JavaScript source exposes more than ${MAX_SOURCE_OPERATIONS} bounded operations` };
  }
  return { paths, executions };
}
