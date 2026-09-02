import { readFileSync, statSync } from "node:fs";
import { dirname, join, parse, resolve } from "node:path";

const MAX_PACKAGE_JSON_BYTES = 262_144;
const NPM_VALUE_OPTIONS = new Set([
  "--cache", "--loglevel", "--prefix", "--registry", "--script-shell", "--userconfig",
  "--workspace", "-w",
]);

export interface NpmLifecycleScript {
  name: string;
  source: string;
  appendArguments: boolean;
}

export interface NpmScriptSelection {
  handled: boolean;
  packageJson?: string;
  packageRoot?: string;
  scripts: NpmLifecycleScript[];
  arguments: string[];
  unresolvedReason?: string;
  dynamicSelection?: boolean;
  key?: string;
}

function isDynamicShellValue(value: string): boolean {
  return /\$(?:[$?!#*@0-9-]|\(|\{|[A-Za-z_])|`/.test(value);
}

function packageJsonFrom(start: string): string | undefined {
  let directory = resolve(start);
  while (true) {
    const candidate = join(directory, "package.json");
    try {
      if (statSync(candidate).isFile()) return candidate;
    } catch { /* Continue toward the filesystem root. */ }
    const parent = dirname(directory);
    if (parent === directory || directory === parse(directory).root) return undefined;
    directory = parent;
  }
}

function optionValue(arg: string): { option: string; inline?: string } {
  const equals = arg.startsWith("--") ? arg.indexOf("=") : -1;
  return equals > 0 ? { option: arg.slice(0, equals), inline: arg.slice(equals + 1) } : { option: arg };
}

/** Resolve npm's local test/run lifecycle without invoking npm or evaluating package code. */
export function selectNpmScripts(args: string[], cwd: string): NpmScriptSelection {
  let prefix = cwd;
  let workspaceSelection = false;
  let dynamicWorkspace = false;
  let dynamicScriptShell = false;
  let explicitScriptShell = false;
  let dynamicPrefix = false;
  let command: string | undefined;
  let commandIndex = -1;

  for (let index = 0; index < args.length; index++) {
    const arg = args[index]!;
    if (!arg.startsWith("-")) { command = arg; commandIndex = index; break; }
    const { option, inline } = optionValue(arg);
    if (!NPM_VALUE_OPTIONS.has(option)) continue;
    const value = inline ?? args[++index];
    if (option === "--prefix" && value) {
      if (isDynamicShellValue(value)) dynamicPrefix = true;
      else prefix = resolve(cwd, value);
    }
    if (option === "--script-shell") {
      explicitScriptShell = true;
      if (value && isDynamicShellValue(value)) dynamicScriptShell = true;
    }
    if (option === "--workspace" || option === "-w") {
      workspaceSelection = true;
      if (value && isDynamicShellValue(value)) dynamicWorkspace = true;
    }
  }

  if (!command) return { handled: false, scripts: [], arguments: [] };
  let scriptName: string | undefined;
  let remainder = args.slice(commandIndex + 1);
  if (["test", "t", "tst"].includes(command)) scriptName = "test";
  else if (command === "run" || command === "run-script") {
    while (remainder[0]?.startsWith("-")) {
      const current = remainder.shift()!;
      const { option, inline } = optionValue(current);
      if (NPM_VALUE_OPTIONS.has(option) && inline === undefined) remainder.shift();
    }
    scriptName = remainder.shift();
    if (!scriptName) return { handled: false, scripts: [], arguments: [] };
  } else return { handled: false, scripts: [], arguments: [] };

  const separator = remainder.indexOf("--");
  const forwarded = separator >= 0 ? remainder.slice(separator + 1) : [];
  if (isDynamicShellValue(scriptName)) {
    return {
      handled: true,
      scripts: [],
      arguments: forwarded,
      unresolvedReason: "npm script name cannot be resolved statically",
      dynamicSelection: true,
    };
  }
  if (dynamicPrefix || explicitScriptShell) {
    const reason = dynamicPrefix
      ? "npm package prefix cannot be resolved statically"
      : "An explicit npm script shell cannot be analyzed as Bash safely";
    return {
      handled: true,
      scripts: [],
      arguments: forwarded,
      unresolvedReason: reason,
      ...((dynamicPrefix || dynamicScriptShell) ? { dynamicSelection: true } : {}),
    };
  }
  if (workspaceSelection) {
    return {
      handled: true,
      scripts: [],
      arguments: forwarded,
      unresolvedReason: "npm workspace script selection cannot be resolved statically",
      ...(dynamicWorkspace ? { dynamicSelection: true } : {}),
    };
  }

  const packageJson = packageJsonFrom(prefix);
  if (!packageJson) {
    return { handled: true, scripts: [], arguments: forwarded, unresolvedReason: `No package.json was found for npm ${scriptName}` };
  }

  try {
    if (statSync(packageJson).size > MAX_PACKAGE_JSON_BYTES) {
      return { handled: true, packageJson, scripts: [], arguments: forwarded, unresolvedReason: `package.json exceeds the 256 KiB inspection limit: ${packageJson}` };
    }
    const manifest = JSON.parse(readFileSync(packageJson, "utf8")) as { scripts?: Record<string, unknown> };
    const definitions = manifest.scripts;
    const main = definitions?.[scriptName];
    if (main === undefined) {
      const packageRoot = dirname(packageJson);
      return { handled: true, packageJson, packageRoot, scripts: [], arguments: forwarded, key: `${packageJson}\0${scriptName}` };
    }
    if (typeof main !== "string") {
      return { handled: true, packageJson, scripts: [], arguments: forwarded, unresolvedReason: `npm script ${scriptName} is not a static string` };
    }
    const ignoreLifecycle = args.some((arg) => arg === "--ignore-scripts" || arg === "--ignore-scripts=true");
    const names = ignoreLifecycle ? [scriptName] : [`pre${scriptName}`, scriptName, `post${scriptName}`];
    const scripts: NpmLifecycleScript[] = [];
    for (const name of names) {
      const source = definitions?.[name];
      if (source === undefined) continue;
      if (typeof source !== "string") {
        return { handled: true, packageJson, scripts: [], arguments: forwarded, unresolvedReason: `npm script ${name} is not a static string` };
      }
      scripts.push({ name, source, appendArguments: name === scriptName });
    }
    const packageRoot = dirname(packageJson);
    return {
      handled: true,
      packageJson,
      packageRoot,
      scripts,
      arguments: forwarded,
      key: `${packageJson}\0${scriptName}`,
    };
  } catch {
    return { handled: true, packageJson, scripts: [], arguments: forwarded, unresolvedReason: `package.json could not be parsed safely: ${packageJson}` };
  }
}
