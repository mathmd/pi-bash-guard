import { existsSync, lstatSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, isAbsolute, join, normalize, relative } from "node:path";
import { homedir } from "node:os";
import type { OwnershipLevel, PolicyFile, PolicyIssue } from "./types.ts";
import { canonicalPath, globToRegExp, isWithin, resolvePath } from "./path-utils.ts";
import { isYoloControlPath } from "./live-yolo.ts";

const DEFAULT_SECRET_PATTERNS = [
  "**/.env", "**/.env.*", "**/.npmrc", "**/.pypirc", "**/.netrc",
  "**/.git-credentials", "**/id_rsa", "**/id_ed25519", "**/id_ecdsa",
  "**/*.pem", "**/*.key", "**/*.p12", "**/*.pfx", "**/*.kdbx",
  "~/.ssh/**", "~/.aws/**", "~/.config/gcloud/**", "~/.kube/config",
  "~/.docker/config.json", "~/.config/gh/hosts.yml", "~/.pi/**/auth.json",
];

export type PolicyScope = "global" | "local";
interface LoadedPolicy { file: PolicyFile; path: string; base: string; scope: PolicyScope; }

type PolicyInput = Omit<PolicyFile, "tools"> & { tools?: PolicyFile["tools"] };
export function emptyPolicy(): PolicyFile {
  return {
    version: 3,
    ownership: { edit: [], execute: [], full: [] },
    secrets: [],
    commands: { include: [], exclude: [] },
    tools: { read: [] },
  };
}

function validateStrings(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new Error(`${field} must be an array of strings`);
  }
  return [...value];
}

function validateCommandEntries(value: unknown, field: string): string[][] {
  if (!Array.isArray(value)) throw new Error(`${field} must be an array`);
  return value.map((entry, index) => {
    if (!Array.isArray(entry) || entry.length === 0 || !entry.every((item) => typeof item === "string")) {
      throw new Error(`${field}[${index}] must be a non-empty array of strings`);
    }
    if (entry.slice(0, -1).includes("**")) throw new Error(`${field}[${index}] may use ** only as its final member`);
    return [...entry];
  });
}

export function parsePermissionTimeout(value: 0 | string | undefined): number {
  if (value === undefined || value === 0) return 0;
  const match = value.match(/^(?:(\d+)m)?(?:(\d+)s)?$/);
  if (!match || (!match[1] && !match[2])) throw new Error("permissionTimeout must be 0 or a duration such as 1m30s");
  const timeoutMs = (Number(match[1] ?? 0) * 60 + Number(match[2] ?? 0)) * 1_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs > 2_147_483_647) throw new Error("permissionTimeout is too large");
  return timeoutMs;
}

export function validatePolicy(value: unknown): PolicyFile {
  if (!value || typeof value !== "object") throw new Error("policy must be an object");
  const obj = value as Record<string, unknown>;
  if (obj.version !== 3) throw new Error("version must be 3; edit this policy manually (automatic migration is disabled)");
  if (!obj.ownership || typeof obj.ownership !== "object" || Array.isArray(obj.ownership)) {
    throw new Error("ownership must contain edit, execute, and full pattern lists");
  }
  const ownership = obj.ownership as Record<string, unknown>;
  const edit = validateStrings(ownership.edit, "ownership.edit");
  const execute = validateStrings(ownership.execute, "ownership.execute");
  const full = validateStrings(ownership.full, "ownership.full");
  const secrets = validateStrings(obj.secrets, "secrets");

  if (!obj.commands || typeof obj.commands !== "object" || Array.isArray(obj.commands)) {
    throw new Error("commands must contain include and exclude entry lists");
  }
  const rawCommands = obj.commands as Record<string, unknown>;
  const commands = {
    include: validateCommandEntries(rawCommands.include, "commands.include"),
    exclude: validateCommandEntries(rawCommands.exclude, "commands.exclude"),
  };

  const rawTools = obj.tools ?? {};
  if (!rawTools || typeof rawTools !== "object" || Array.isArray(rawTools)) throw new Error("tools must contain a read list");
  const readTools = validateStrings((rawTools as Record<string, unknown>).read ?? [], "tools.read");
  const permissionTimeout = obj.permissionTimeout as 0 | string | undefined;
  if (permissionTimeout !== undefined && permissionTimeout !== 0 && typeof permissionTimeout !== "string") {
    throw new Error("permissionTimeout must be 0 or a duration string");
  }
  parsePermissionTimeout(permissionTimeout);
  return {
    version: 3,
    ownership: { edit, execute, full },
    secrets,
    commands,
    tools: { read: readTools },
    ...(permissionTimeout === undefined ? {} : { permissionTimeout }),
  };
}

function parseOwnershipPattern(entry: string): { pattern: string; included: boolean } | undefined {
  let value = entry.trim();
  if (!value || value.startsWith("#")) return undefined;
  if (value.startsWith("\\!") || value.startsWith("\\#")) value = value.slice(1);
  else if (value.startsWith("!")) return { pattern: value.slice(1), included: false };
  return { pattern: value, included: true };
}

function commandGlob(pattern: string): RegExp {
  let source = "^";
  let escaped = false;
  for (const character of pattern) {
    if (escaped) {
      source += character.replace(/[\\^$.*+?()[\]{}|]/g, "\\$&");
      escaped = false;
    } else if (character === "\\") escaped = true;
    else if (character === "*") source += ".*";
    else if (character === "?") source += ".";
    else source += character.replace(/[\\^$.*+?()[\]{}|]/g, "\\$&");
  }
  if (escaped) source += "\\\\";
  return new RegExp(`${source}$`);
}

function escapeCommandPattern(value: string): string {
  return value.replace(/[\\*?]/g, "\\$&");
}

function unorderedArgumentsMatch(patterns: string[], args: string[], allowRest: boolean): boolean {
  if (patterns.length > args.length || (!allowRest && patterns.length !== args.length)) return false;
  const used = new Set<number>();
  const visit = (patternIndex: number): boolean => {
    if (patternIndex === patterns.length) return true;
    const expression = commandGlob(patterns[patternIndex]!);
    for (let argIndex = 0; argIndex < args.length; argIndex++) {
      if (used.has(argIndex) || !expression.test(args[argIndex]!)) continue;
      used.add(argIndex);
      if (visit(patternIndex + 1)) return true;
      used.delete(argIndex);
    }
    return false;
  };
  return visit(0);
}

function commandEntryMatches(entry: string[], name: string, args: string[]): boolean {
  if (!commandGlob(entry[0]!).test(name)) return false;
  const allowRest = entry.at(-1) === "**";
  const patterns = allowRest ? entry.slice(1, -1) : entry.slice(1);
  return unorderedArgumentsMatch(patterns, args, allowRest);
}

export interface ProcessIoRoots {
  deviceRoot: string;
  processFdRoot: string;
}
export class PolicyStore {
  readonly home: string;
  readonly globalPath: string;
  private cwd: string;
  private localPath: string;
  private policies: LoadedPolicy[] = [];
  private issues: PolicyIssue[] = [];
  private transientRun = new Set<string>();
  private transientSession = new Set<string>();
  private trustLocal = true;
  private readonly systemReadonlyRoots: string[];
  private readonly processIoRoots: ProcessIoRoots;
  private gitTrackedPaths = new Set<string>();

  constructor(
    policyDir: string,
    cwd: string,
    home = homedir(),
    systemReadonlyRoots = ["/nix/store"],
    processIoRoots: ProcessIoRoots = { deviceRoot: "/dev", processFdRoot: "/proc/self/fd" },
  ) {
    this.home = home;
    this.systemReadonlyRoots = systemReadonlyRoots.map(canonicalPath);
    this.processIoRoots = {
      deviceRoot: normalize(processIoRoots.deviceRoot),
      processFdRoot: normalize(processIoRoots.processFdRoot),
    };
    this.globalPath = join(policyDir, "policy.json");
    this.cwd = canonicalPath(cwd);
    this.localPath = join(this.cwd, ".pi", "bash-guard.json");
    this.reload(true);
    this.refreshGitOwnership();
  }

  configure(cwd: string, trustLocal: boolean): void {
    this.cwd = canonicalPath(cwd);
    this.localPath = join(this.cwd, ".pi", "bash-guard.json");
    this.trustLocal = trustLocal;
    this.reload();
    this.refreshGitOwnership();
  }

  refreshGitOwnership(): void {
    this.gitTrackedPaths.clear();
    const options = { encoding: "utf8" as const, timeout: 2_000, maxBuffer: 32 * 1024 * 1024, windowsHide: true };
    const rootResult = spawnSync("git", ["-C", this.cwd, "rev-parse", "--show-toplevel"], options);
    if (rootResult.status !== 0 || !rootResult.stdout.trim()) return;
    const root = canonicalPath(rootResult.stdout.trim());
    const filesResult = spawnSync("git", ["-C", root, "ls-files", "--cached", "--full-name", "-z"], options);
    if (filesResult.status !== 0) return;
    for (const relativePath of filesResult.stdout.split("\0")) {
      if (!relativePath) continue;
      const lexicalPath = normalize(join(root, relativePath));
      try {
        if (lstatSync(lexicalPath).isSymbolicLink()) continue;
      } catch { /* Deleted tracked paths still retain edit ownership. */ }
      this.gitTrackedPaths.add(canonicalPath(lexicalPath));
    }
  }

  private load(path: string, base: string, scope: PolicyScope): LoadedPolicy {
    try {
      return { file: validatePolicy(JSON.parse(readFileSync(path, "utf8"))), path, base, scope };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") this.issues.push({ path, message: String(error) });
      return { file: emptyPolicy(), path, base, scope };
    }
  }

  reload(trustLocal = this.trustLocal): void {
    this.trustLocal = trustLocal;
    this.issues = [];
    this.policies = [this.load(this.globalPath, this.home, "global")];
    if (trustLocal) this.policies.push(this.load(this.localPath, this.cwd, "local"));
  }

  getPolicyPath(scope: PolicyScope): string { return scope === "global" ? this.globalPath : this.localPath; }
  getLocalPath(): string { return this.localPath; }
  getIssues(): PolicyIssue[] { return [...this.issues]; }
  getPolicies(): ReadonlyArray<LoadedPolicy> { return this.policies; }

  isPolicyPath(path: string): boolean {
    const canonical = canonicalPath(path);
    return canonical === canonicalPath(this.globalPath) || canonical === canonicalPath(this.localPath);
  }

  isSystemReadonlyPath(path: string): boolean {
    const canonical = canonicalPath(path);
    return this.systemReadonlyRoots.some((root) => isWithin(canonical, root));
  }

  isSafeProcessIoPath(path: string): boolean {
    const lexical = normalize(path);
    const deviceRelative = relative(this.processIoRoots.deviceRoot, lexical);
    if (["null", "full", "zero", "stdin", "stdout", "stderr", "tty"].includes(deviceRelative)) return true;
    if (/^fd[/\\][012]$/.test(deviceRelative)) return true;
    return /^[012]$/.test(relative(this.processIoRoots.processFdRoot, lexical));
  }

  addCreated(path: string): void {
    const canonical = canonicalPath(path);
    if (isWithin(canonical, "/tmp")) this.transientSession.add(canonical);
    else this.transientRun.add(canonical);
  }
  clearRunOwnership(): void { this.transientRun.clear(); }
  clearSessionOwnership(): void { this.transientRun.clear(); this.transientSession.clear(); }

  private compileSinglePattern(rawPattern: string, base: string): RegExp {
    let raw = rawPattern;
    const hasSlash = raw.includes("/");
    if (raw.startsWith("~")) raw = resolvePath(raw, base, this.home);
    else if (!isAbsolute(raw)) raw = normalize(join(base, hasSlash ? raw : `**/${raw}`));

    const wildcard = raw.search(/[?*]/);
    if (wildcard < 0) return globToRegExp(canonicalPath(raw));
    const fixed = raw.slice(0, wildcard);
    const trailingSeparator = fixed.endsWith("/");
    const canonicalFixed = canonicalPath(trailingSeparator ? fixed.slice(0, -1) : fixed);
    return globToRegExp(normalize(`${canonicalFixed}${trailingSeparator ? "/" : ""}${raw.slice(wildcard)}`));
  }

  private compilePattern(rawPattern: string, base: string): RegExp {
    if (!rawPattern.endsWith("/")) return this.compileSinglePattern(rawPattern, base);
    const directory = rawPattern.slice(0, -1);
    const exact = this.compileSinglePattern(directory, base);
    const descendants = this.compileSinglePattern(`${directory}/**`, base);
    return new RegExp(`(?:${exact.source})|(?:${descendants.source})`);
  }

  private includedIn(level: "edit" | "execute" | "full", canonical: string): boolean {
    let included = false;
    for (const policy of this.policies) {
      for (const entry of policy.file.ownership[level]) {
        const parsed = parseOwnershipPattern(entry);
        if (parsed && this.compilePattern(parsed.pattern, policy.base).test(canonical)) included = parsed.included;
      }
    }
    return included;
  }

  ownership(path: string): OwnershipLevel {
    const canonical = canonicalPath(path);
    if (this.includedIn("full", canonical)) return "full";
    const transientEdit = [...this.transientRun, ...this.transientSession].some((root) => isWithin(canonical, root));
    const canEdit = transientEdit || this.gitTrackedPaths.has(canonical) || this.includedIn("edit", canonical);
    const canExecute = this.includedIn("execute", canonical);
    if (canEdit && canExecute) return "full";
    if (canEdit) return "edit";
    if (canExecute) return "execute";
    return "read";
  }

  isSecret(path: string): boolean {
    const canonical = canonicalPath(path);
    if (isYoloControlPath(path) || isYoloControlPath(canonical)) return true;
    for (const entry of DEFAULT_SECRET_PATTERNS) {
      const pattern = entry.startsWith("~") ? resolvePath(entry, this.home, this.home) : entry;
      if (globToRegExp(pattern).test(canonical)) return true;
    }
    for (const policy of this.policies) {
      for (const entry of policy.file.secrets) {
        if (this.compilePattern(entry, policy.base).test(canonical)) return true;
      }
    }
    return false;
  }

  isTrustedCommand(name: string, args: string[]): boolean {
    const included = this.policies.some((policy) =>
      policy.file.commands.include.some((entry) => commandEntryMatches(entry, name, args)));
    if (!included) return false;
    return !this.policies.some((policy) =>
      policy.file.commands.exclude.some((entry) => commandEntryMatches(entry, name, args)));
  }

  permissionTimeoutMs(): number {
    const value = this.policies.findLast((policy) => policy.file.permissionTimeout !== undefined)?.file.permissionTimeout;
    return parsePermissionTimeout(value);
  }

  isReadOnlyTool(name: string): boolean {
    return this.policies.some((policy) => policy.file.tools.read.includes(name));
  }

  private write(scope: PolicyScope, file: PolicyFile): { path: string; content: string } {
    const path = this.getPolicyPath(scope);
    const content = `${JSON.stringify(validatePolicy(file), null, 2)}\n`;
    mkdirSync(dirname(path), { recursive: true });
    const temporary = `${path}.tmp-${process.pid}`;
    writeFileSync(temporary, content, { mode: 0o600 });
    renameSync(temporary, path);
    this.reload();
    return { path, content };
  }

  save(scope: PolicyScope, file: PolicyInput): void {
    this.write(scope, validatePolicy(file));
  }

  ensurePolicy(scope: PolicyScope): string {
    const path = this.getPolicyPath(scope);
    if (!existsSync(path)) this.write(scope, scope === "global" ? { ...emptyPolicy(), permissionTimeout: 0 } : emptyPolicy());
    return path;
  }

  appendOwnership(scope: PolicyScope, level: "edit" | "execute" | "full", path: string): { path: string; line: number } {
    const policyPath = this.ensurePolicy(scope);
    const current = validatePolicy(JSON.parse(readFileSync(policyPath, "utf8")));
    const pattern = canonicalPath(path);
    current.ownership[level].push(pattern);
    const written = this.write(scope, current);
    const quoted = JSON.stringify(pattern);
    const lines = written.content.split("\n");
    const line = lines.findLastIndex((value) => value.includes(quoted)) + 1;
    return { path: written.path, line: Math.max(1, line) };
  }

  appendTrustedCommand(scope: PolicyScope, name: string, args: string[]): { path: string; line: number } {
    const policyPath = this.ensurePolicy(scope);
    const current = validatePolicy(JSON.parse(readFileSync(policyPath, "utf8")));
    const entry = [name, ...args].map(escapeCommandPattern);
    if (!current.commands.include.some((existing) =>
      existing.length === entry.length && existing.every((value, index) => value === entry[index]))) {
      current.commands.include.push(entry);
    }
    const written = this.write(scope, current);
    const lines = written.content.split("\n");
    const includeStart = lines.findIndex((value) => value.includes('"include"'));
    const excludeStart = lines.findIndex((value, index) => index > includeStart && value.includes('"exclude"'));
    const boundary = excludeStart < 0 ? lines.length : excludeStart;
    let entryStart = boundary - 1;
    while (entryStart > includeStart && lines[entryStart]?.trim() !== "[") entryStart--;
    return { path: written.path, line: Math.max(1, entryStart + 2) };
  }

  appendReadOnlyTool(scope: PolicyScope, name: string): { path: string; line: number } {
    const policyPath = this.ensurePolicy(scope);
    const current = validatePolicy(JSON.parse(readFileSync(policyPath, "utf8")));
    if (!current.tools.read.includes(name)) current.tools.read.push(name);
    const written = this.write(scope, current);
    const quoted = JSON.stringify(name);
    const lines = written.content.split("\n");
    const line = lines.findLastIndex((value) => value.includes(quoted)) + 1;
    return { path: written.path, line: Math.max(1, line) };
  }
}
