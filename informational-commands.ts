export interface InformationalInvocation {
  handled: boolean;
  readPaths: string[];
}

const EMPTY: InformationalInvocation = { handled: false, readPaths: [] };
const HELP_VERSION_FLAGS = new Set(["-h", "--help", "-v", "-V", "--version"]);
const RUNTIME_INFORMATION_FLAGS = new Map<string, Set<string>>([
  ["node", new Set([...HELP_VERSION_FLAGS, "--v8-options", "--completion-bash"])],
  ["python", new Set(["-h", "--help", "-V", "--version", "--help-env", "--help-xoptions", "--help-all"])],
  ["python3", new Set(["-h", "--help", "-V", "--version", "--help-env", "--help-xoptions", "--help-all"])],
  ["julia", new Set(HELP_VERSION_FLAGS)],
  ["ruby", new Set(HELP_VERSION_FLAGS)],
  ["perl", new Set(HELP_VERSION_FLAGS)],
  ["lua", new Set(HELP_VERSION_FLAGS)],
  ["luajit", new Set(HELP_VERSION_FLAGS)],
  ["deno", new Set(HELP_VERSION_FLAGS)],
  ["bun", new Set(HELP_VERSION_FLAGS)],
]);

const NPM_OPTIONS_WITH_VALUES = new Set([
  "--cache", "--color", "--globalconfig", "--loglevel", "--otp", "--prefix", "--registry",
  "--scope", "--tag", "--userconfig", "--workspace", "-w",
]);
const NPM_INFORMATION_COMMANDS = new Set([
  "completion", "explain", "fund", "help", "help-search", "info", "list", "ll", "ls", "outdated",
  "ping", "prefix", "query", "root", "search", "show", "view", "whoami",
]);

function firstCommand(args: string[], valueOptions: Set<string>): { command?: string; rest: string[] } {
  for (let index = 0; index < args.length; index++) {
    const argument = args[index]!;
    if (argument === "--") return { command: args[index + 1], rest: args.slice(index + 2) };
    if (valueOptions.has(argument)) { index++; continue; }
    if ([...valueOptions].some((option) => option.startsWith("--") && argument.startsWith(`${option}=`))) continue;
    if (!argument.startsWith("-")) return { command: argument, rest: args.slice(index + 1) };
  }
  return { rest: [] };
}

function requestsFix(args: string[]): boolean {
  return args.some((argument) => argument === "fix" || argument === "--fix" ||
    (argument.startsWith("--fix=") && !["false", "0"].includes(argument.slice("--fix=".length).toLowerCase())));
}

function npmInvocation(args: string[]): InformationalInvocation {
  if (!args.length) return { handled: true, readPaths: [] };
  if (args.length && args.every((argument) => HELP_VERSION_FLAGS.has(argument) || ["--versions", "--json"].includes(argument))) {
    return { handled: true, readPaths: [] };
  }
  const { command, rest } = firstCommand(args, NPM_OPTIONS_WITH_VALUES);
  if (!command) return EMPTY;
  if (NPM_INFORMATION_COMMANDS.has(command)) return { handled: true, readPaths: [] };
  if (command === "version" && rest.every((argument) => ["--json", "--parseable", "--workspaces", "--include-workspace-root"].includes(argument))) {
    return { handled: true, readPaths: [] };
  }
  if (command === "audit" && !requestsFix(rest)) return { handled: true, readPaths: [] };
  if (command === "config" && (!rest.length || ["get", "list", "ls"].includes(rest.find((argument) => !argument.startsWith("-")) ?? ""))) {
    return { handled: true, readPaths: [] };
  }
  if (command === "pkg" && rest.find((argument) => !argument.startsWith("-")) === "get") return { handled: true, readPaths: [] };
  if (["access", "org", "owner", "profile", "team", "token"].includes(command) &&
    ["get", "list", "ls", "whoami"].includes(rest.find((argument) => !argument.startsWith("-")) ?? "")) {
    return { handled: true, readPaths: [] };
  }
  return EMPTY;
}

const PIP_OPTIONS_WITH_VALUES = new Set([
  "--cache-dir", "--cert", "--client-cert", "--config-settings", "--index-url", "--log", "--proxy",
  "--python", "--retries", "--timeout", "--trusted-host", "--use-feature", "--use-deprecated", "-C",
]);
const PIP_INFORMATION_COMMANDS = new Set(["check", "debug", "freeze", "help", "inspect", "list", "search", "show"]);

function pipInvocation(args: string[]): InformationalInvocation {
  if (!args.length) return { handled: true, readPaths: [] };
  if (args.length && args.every((argument) => HELP_VERSION_FLAGS.has(argument))) return { handled: true, readPaths: [] };
  const { command, rest } = firstCommand(args, PIP_OPTIONS_WITH_VALUES);
  if (!command) return EMPTY;
  if (PIP_INFORMATION_COMMANDS.has(command)) return { handled: true, readPaths: [] };
  if (command === "index" && rest.find((argument) => !argument.startsWith("-")) === "versions") return { handled: true, readPaths: [] };
  if (command === "config" && ["debug", "get", "list"].includes(rest.find((argument) => !argument.startsWith("-")) ?? "")) {
    return { handled: true, readPaths: [] };
  }
  if (command === "cache" && ["dir", "info", "list"].includes(rest.find((argument) => !argument.startsWith("-")) ?? "")) {
    return { handled: true, readPaths: [] };
  }
  if (command === "hash") {
    return { handled: true, readPaths: rest.filter((argument) => !argument.startsWith("-")) };
  }
  return EMPTY;
}

function packageManagerInvocation(command: string, args: string[]): InformationalInvocation {
  if (args.length && args.every((argument) => HELP_VERSION_FLAGS.has(argument))) return { handled: true, readPaths: [] };
  const first = args.find((argument) => !argument.startsWith("-"));
  if (!first) return EMPTY;
  if (command === "pnpm") {
    if (["audit", "info", "licenses", "list", "ls", "outdated", "root", "search", "view", "why"].includes(first) && !requestsFix(args)) {
      return { handled: true, readPaths: [] };
    }
    if (first === "config" && ["get", "list"].includes(args.find((argument, index) => index > args.indexOf(first) && !argument.startsWith("-")) ?? "")) {
      return { handled: true, readPaths: [] };
    }
  }
  if (command === "yarn") {
    if (["info", "list", "outdated", "why"].includes(first)) return { handled: true, readPaths: [] };
    if (first === "config" && ["get", "list"].includes(args.find((argument, index) => index > args.indexOf(first) && !argument.startsWith("-")) ?? "")) {
      return { handled: true, readPaths: [] };
    }
  }
  if (command === "bun" && first === "pm" && ["ls", "hash", "hash-string"].includes(args.find((argument, index) => index > args.indexOf(first) && !argument.startsWith("-")) ?? "")) {
    return { handled: true, readPaths: [] };
  }
  return EMPTY;
}
const INFORMATION_ONLY_TOOLS = new Set(["cargo", "dotnet", "gem", "npx", "pipx", "poetry", "uv"]);


/** Return only curated invocations whose documented purpose is inspection. */
export function informationalInvocation(command: string, args: string[]): InformationalInvocation {
  if (command === "npm") return npmInvocation(args);
  if (["pip", "pip3"].includes(command)) return pipInvocation(args);
  if (["pnpm", "yarn"].includes(command)) return packageManagerInvocation(command, args);
  if (INFORMATION_ONLY_TOOLS.has(command) && args.length && args.every((argument) => HELP_VERSION_FLAGS.has(argument) || ["--info", "--list"].includes(argument))) {
    return { handled: true, readPaths: [] };
  }
  if (command === "go" && args.length && (["version", "help"].includes(args[0]!) || args.every((argument) => HELP_VERSION_FLAGS.has(argument)))) {
    return { handled: true, readPaths: [] };
  }

  const runtimeFlags = RUNTIME_INFORMATION_FLAGS.get(command);
  if (runtimeFlags && args.length && args.every((argument) => runtimeFlags.has(argument))) return { handled: true, readPaths: [] };

  if (command === "node") {
    const check = args.findIndex((argument) => argument === "--check" || argument === "-c");
    const before = args.slice(0, check);
    const after = args.slice(check + 2);
    const safeCheckOption = (argument: string): boolean => /^--input-type=(?:commonjs|module)$/.test(argument);
    if (check >= 0 && args[check + 1] && before.every(safeCheckOption) && after.every(safeCheckOption)) {
      return { handled: true, readPaths: [args[check + 1]!] };
    }
  }
  if (["python", "python3"].includes(command)) {
    const moduleIndex = args.findIndex((argument) => argument === "-m");
    if (moduleIndex >= 0 && args[moduleIndex + 1] === "pip") return pipInvocation(args.slice(moduleIndex + 2));
    if (moduleIndex >= 0 && ["platform", "site", "sysconfig"].includes(args[moduleIndex + 1] ?? "") &&
      args.slice(moduleIndex + 2).every((argument) => HELP_VERSION_FLAGS.has(argument) || argument.startsWith("--user-"))) {
      return { handled: true, readPaths: [] };
    }
  }
  if (command === "bun") return packageManagerInvocation(command, args);
  return EMPTY;
}
