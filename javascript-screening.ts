import { parse } from "@babel/parser";

interface AstNode {
  type: string;
  [key: string]: unknown;
}

type ChildProcessSink = "shell" | "argv" | "module";
const DYNAMIC_JAVASCRIPT_VALUE = "__bash_guard_dynamic_javascript_value__";

export type JavaScriptExecution =
  | { kind: "shell"; command: string }
  | { kind: "argv"; executable: string; args: string[] }
  | { kind: "module"; path: string };

export interface JavaScriptScreening {
  executions: JavaScriptExecution[];
  parseError?: string;
}

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
    "TypeCastExpression", "ParenthesizedExpression",
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
      if (!isNode(quasi) || !isNode(quasi.value) || typeof quasi.value.cooked !== "string") return undefined;
      value += quasi.value.cooked;
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

function arrayValue(node: unknown, strings: Map<string, string>, arrays: Map<string, string[]>): string[] | undefined {
  node = unwrap(node);
  if (!isNode(node)) return undefined;
  if (node.type === "Identifier" && typeof node.name === "string") return arrays.get(node.name);
  if (node.type !== "ArrayExpression" || !Array.isArray(node.elements)) return undefined;
  const values: string[] = [];
  for (const element of node.elements) {
    values.push(stringValue(element, strings) ?? DYNAMIC_JAVASCRIPT_VALUE);
  }
  return values;
}

function callArguments(node: AstNode): unknown[] {
  return Array.isArray(node.arguments) ? node.arguments : [];
}

function requiredModule(node: unknown, strings: Map<string, string>): string | undefined {
  node = unwrap(node);
  if (!isNode(node) || node.type !== "CallExpression" || identifierName(node.callee) !== "require") return undefined;
  return stringValue(callArguments(node)[0], strings);
}

function isChildProcessModule(value: string | undefined): boolean {
  return value === "child_process" || value === "node:child_process";
}

function importedName(specifier: AstNode): string | undefined {
  return propertyName(specifier.imported);
}

const CHILD_PROCESS_SINKS = new Map<string, ChildProcessSink>([
  ["exec", "shell"], ["execSync", "shell"],
  ["execFile", "argv"], ["execFileSync", "argv"],
  ["spawn", "argv"], ["spawnSync", "argv"],
  ["fork", "module"],
]);

function memberParts(node: unknown): { object?: string; property?: string; required?: string } {
  node = unwrap(node);
  if (!isNode(node) || ["MemberExpression", "OptionalMemberExpression"].includes(node.type) === false) return {};
  const object = identifierName(node.object);
  const property = propertyName(node.property);
  const required = requiredModule(node.object, new Map());
  return { object, property, required };
}

/**
 * Parse JavaScript/TypeScript and return only concrete strings passed to known
 * Node child-process execution APIs. Ordinary literals and test fixtures remain data.
 */
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
    return { executions: [], parseError: error instanceof Error ? error.message : String(error) };
  }

  const strings = new Map<string, string>();
  const arrays = new Map<string, string[]>();
  const declarators: AstNode[] = [];
  const functions = new Map<string, ChildProcessSink>();
  const namespaces = new Set<string>();
  const declaratorCounts = new Map<string, number>();

  walk(root, (node) => {
    if (node.type === "ImportDeclaration" && isNode(node.source) && typeof node.source.value === "string" &&
      isChildProcessModule(node.source.value) && Array.isArray(node.specifiers)) {
      for (const specifier of node.specifiers) {
        if (!isNode(specifier)) continue;
        const local = identifierName(specifier.local);
        if (!local) continue;
        if (specifier.type === "ImportNamespaceSpecifier" || specifier.type === "ImportDefaultSpecifier") namespaces.add(local);
        else {
          const sink = CHILD_PROCESS_SINKS.get(importedName(specifier) ?? "");
          if (sink) functions.set(local, sink);
        }
      }
    }
    if (node.type === "VariableDeclaration" && node.kind === "const" && Array.isArray(node.declarations)) {
      for (const declaration of node.declarations) {
        if (!isNode(declaration)) continue;
        declarators.push(declaration);
        const local = identifierName(declaration.id);
        if (local) declaratorCounts.set(local, (declaratorCounts.get(local) ?? 0) + 1);
        if (isNode(declaration.id) && declaration.id.type === "ObjectPattern" && Array.isArray(declaration.id.properties)) {
          for (const property of declaration.id.properties) {
            const alias = isNode(property) ? identifierName(property.value) : undefined;
            if (alias) declaratorCounts.set(alias, (declaratorCounts.get(alias) ?? 0) + 1);
          }
        }
      }
    }
  });

  // Resolve simple const-style aliases and literal command values without executing code.
  for (let pass = 0; pass < declarators.length + 1; pass++) {
    let changed = false;
    for (const declaration of declarators) {
      const local = identifierName(declaration.id);
      if (local) {
        if ((declaratorCounts.get(local) ?? 0) !== 1) continue;
        const value = stringValue(declaration.init, strings);
        if (value !== undefined && strings.get(local) !== value) { strings.set(local, value); changed = true; }
        const values = arrayValue(declaration.init, strings, arrays);
        if (values && arrays.get(local)?.join("\0") !== values.join("\0")) { arrays.set(local, values); changed = true; }
        const required = requiredModule(declaration.init, strings);
        if (isChildProcessModule(required) && !namespaces.has(local)) { namespaces.add(local); changed = true; }
        const alias = identifierName(unwrap(declaration.init));
        const sink = alias ? functions.get(alias) : undefined;
        if (sink && functions.get(local) !== sink) { functions.set(local, sink); changed = true; }
      } else if (isNode(declaration.id) && declaration.id.type === "ObjectPattern" && Array.isArray(declaration.id.properties) &&
        isChildProcessModule(requiredModule(declaration.init, strings))) {
        for (const property of declaration.id.properties) {
          if (!isNode(property) || property.type !== "ObjectProperty") continue;
          const sink = CHILD_PROCESS_SINKS.get(propertyName(property.key) ?? "");
          const alias = identifierName(property.value);
          if (alias && (declaratorCounts.get(alias) ?? 0) !== 1) continue;
          if (sink && alias && functions.get(alias) !== sink) { functions.set(alias, sink); changed = true; }
        }
      }
    }
    if (!changed) break;
  }

  const executions: JavaScriptExecution[] = [];
  walk(root, (node) => {
    if (node.type !== "CallExpression" && node.type !== "OptionalCallExpression") return;
    const callee = unwrap(node.callee);
    let sink = identifierName(callee) ? functions.get(identifierName(callee)!) : undefined;
    if (!sink) {
      const member = memberParts(callee);
      if ((member.object && namespaces.has(member.object)) || isChildProcessModule(member.required)) {
        sink = CHILD_PROCESS_SINKS.get(member.property ?? "");
      }
    }
    if (!sink) return;

    const args = callArguments(node);
    const first = stringValue(args[0], strings);
    if (first === undefined) return;
    if (sink === "shell") executions.push({ kind: "shell", command: first });
    else if (sink === "module") executions.push({ kind: "module", path: first });
    else {
      const argv = arrayValue(args[1], strings, arrays);
      executions.push({ kind: "argv", executable: first, args: argv ?? [] });
    }
  });

  return { executions };
}
