import { globSync, readdirSync, statSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const MAX_NODE_TEST_FILES = 512;
const TEST_EXTENSIONS = new Set([".js", ".cjs", ".mjs", ".ts", ".cts", ".mts"]);
const JAVASCRIPT_TEST_EXTENSIONS = new Set([".js", ".cjs", ".mjs"]);
const DEFAULT_TEST_PATTERNS = [
  "**/*.test.{cjs,mjs,js,cts,mts,ts}",
  "**/*-test.{cjs,mjs,js,cts,mts,ts}",
  "**/*_test.{cjs,mjs,js,cts,mts,ts}",
  "**/test-*.{cjs,mjs,js,cts,mts,ts}",
  "**/test.{cjs,mjs,js,cts,mts,ts}",
  "**/test/**/*.{cjs,mjs,js,cts,mts,ts}",
];
const DEFAULT_JAVASCRIPT_TEST_PATTERNS = DEFAULT_TEST_PATTERNS.map((pattern) =>
  pattern.replace("{cjs,mjs,js,cts,mts,ts}", "{cjs,mjs,js}"));

// Options whose following token is option data rather than a test target.
const NODE_VALUE_OPTIONS = new Set([
  "--conditions", "--diagnostic-dir", "--disable-warning", "--dns-result-order", "--env-file",
  "--experimental-loader", "--loader", "--experimental-test-isolation", "--heapsnapshot-near-heap-limit", "--icu-data-dir", "--input-type",
  "--inspect-port", "--max-http-header-size", "--openssl-config", "--redirect-warnings", "--require",
  "--secure-heap", "--secure-heap-min", "--snapshot-blob", "--test-concurrency",
  "--test-coverage-branches", "--test-coverage-exclude", "--test-coverage-functions",
  "--test-coverage-include", "--test-coverage-lines", "--test-global-setup", "--test-name-pattern",
  "--test-isolation", "--test-random-seed", "--test-reporter", "--test-reporter-destination",
  "--test-rerun-failures", "--test-shard", "--test-skip-pattern",
  "--test-timeout", "--title", "--trace-event-categories", "--trace-event-file-pattern",
  "--unhandled-rejections", "--use-largepages", "--watch-path", "--import", "-r",
]);
const EXECUTED_OPTION_PATHS = new Set([
  "--experimental-loader", "--loader", "--import", "--require", "-r", "--test-global-setup", "--test-reporter",
]);

export interface NodeTestSelection {
  enabled: boolean;
  files: string[];
  supportFiles: string[];
  reporterDestinations: string[];
  truncated: boolean;
  unresolved: boolean;
}

function isDynamicShellValue(value: string): boolean {
  return /\$(?:[$?!#*@0-9-]|\(|\{|[A-Za-z_])|`/.test(value);
}

function extension(path: string): string {
  const dot = path.lastIndexOf(".");
  return dot < 0 ? "" : path.slice(dot).toLowerCase();
}

function isLocalModuleSpecifier(value: string): boolean {
  return isAbsolute(value) || value.startsWith("./") || value.startsWith("../") || value.startsWith("file:");
}

function localModulePath(value: string, cwd: string): string | undefined {
  if (!isLocalModuleSpecifier(value)) return undefined;
  try {
    return value.startsWith("file:") ? fileURLToPath(value) : resolve(cwd, value);
  } catch {
    return undefined;
  }
}

function addUniqueFile(files: string[], path: string): void {
  if (!files.includes(path)) files.push(path);
}

function addDirectoryFiles(directory: string, files: string[], extensions: Set<string>): void {
  if (files.length > MAX_NODE_TEST_FILES) return;
  let entries;
  try { entries = readdirSync(directory, { withFileTypes: true }); }
  catch { return; }
  for (const entry of entries) {
    if (files.length > MAX_NODE_TEST_FILES) return;
    if (entry.name === "node_modules" || entry.name === ".git") continue;
    const path = join(directory, entry.name);
    if (entry.isDirectory()) addDirectoryFiles(path, files, extensions);
    else if (entry.isFile() && extensions.has(extension(path))) addUniqueFile(files, path);
  }
}

function expandTarget(target: string, cwd: string, files: string[], extensions: Set<string>): void {
  if (/[*?{\[]/.test(target)) {
    try {
      for (const match of globSync(target, { cwd, exclude: ["node_modules/**", ".git/**"] })) {
        if (files.length > MAX_NODE_TEST_FILES) return;
        expandTarget(isAbsolute(match) ? match : resolve(cwd, match), cwd, files, extensions);
      }
    } catch { /* Node will report an invalid or unmatched test glob. */ }
    return;
  }

  const path = resolve(cwd, target);
  try {
    const stat = statSync(path);
    if (stat.isDirectory()) addDirectoryFiles(path, files, extensions);
    else if (stat.isFile()) addUniqueFile(files, path);
  } catch {
    // Retain an explicit missing target. The analyzer records it as a literal execute path;
    // Node itself will fail before executing it.
    addUniqueFile(files, path);
  }
}

/** Resolve the files Node's built-in test runner can execute without running Node itself. */
export function selectNodeTestFiles(args: string[], cwd: string): NodeTestSelection {
  let enabled = false;
  let afterSeparator = false;
  let sawPositionalBeforeTest = false;
  const targets: string[] = [];
  const supportFiles: string[] = [];
  const reporterDestinations: string[] = [];
  let discoveryFailed = false;

  for (let index = 0; index < args.length; index++) {
    const arg = args[index]!;
    if (afterSeparator) { targets.push(arg); continue; }
    if (arg === "--") { afterSeparator = true; continue; }
    if (arg === "--test") { if (!sawPositionalBeforeTest) enabled = true; continue; }

    const equals = arg.startsWith("--") ? arg.indexOf("=") : -1;
    const option = equals > 0 ? arg.slice(0, equals) : arg;
    if (NODE_VALUE_OPTIONS.has(option)) {
      const value = equals > 0 ? arg.slice(equals + 1) : args[++index];
      if (value && EXECUTED_OPTION_PATHS.has(option)) {
        if (isDynamicShellValue(value)) discoveryFailed = true;
        else {
          const path = localModulePath(value, cwd);
          if (path) supportFiles.push(path);
        }
      }
      if (value && option === "--test-reporter-destination" && value !== "stdout" && value !== "stderr") {
        if (isDynamicShellValue(value)) discoveryFailed = true;
        else reporterDestinations.push(resolve(cwd, value));
      }
      continue;
    }
    if (/^-r.+/.test(arg)) {
      const value = arg.slice(2);
      if (isDynamicShellValue(value)) discoveryFailed = true;
      else {
        const path = localModulePath(value, cwd);
        if (path) supportFiles.push(path);
      }
      continue;
    }
    if (arg.startsWith("-")) continue;
    if (!enabled) { sawPositionalBeforeTest = true; continue; }
    targets.push(arg);
  }

  if (!enabled) return { enabled: false, files: [], supportFiles: [], reporterDestinations: [], truncated: false, unresolved: false };

  const extensions = args.includes("--no-strip-types") ? JAVASCRIPT_TEST_EXTENSIONS : TEST_EXTENSIONS;
  const files: string[] = [];
  if (targets.length) {
    for (const target of targets) {
      if (isDynamicShellValue(target)) discoveryFailed = true;
      else expandTarget(target, cwd, files, extensions);
    }
  } else {
    const patterns = args.includes("--no-strip-types") ? DEFAULT_JAVASCRIPT_TEST_PATTERNS : DEFAULT_TEST_PATTERNS;
    for (const pattern of patterns) {
      try {
        for (const match of globSync(pattern, { cwd, exclude: ["node_modules/**", ".git/**"] })) {
          if (files.length > MAX_NODE_TEST_FILES) break;
          addUniqueFile(files, resolve(cwd, match));
        }
      } catch { discoveryFailed = true; }
      if (files.length > MAX_NODE_TEST_FILES) break;
    }
  }

  const unique = [...new Set(files)].sort();
  return {
    enabled: true,
    files: unique.slice(0, MAX_NODE_TEST_FILES),
    supportFiles: [...new Set(supportFiles)].sort(),
    reporterDestinations: [...new Set(reporterDestinations)].sort(),
    truncated: unique.length > MAX_NODE_TEST_FILES,
    unresolved: discoveryFailed,
  };
}
