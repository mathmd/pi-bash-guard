import { existsSync, lstatSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, isAbsolute, join, normalize } from "node:path";
import { homedir } from "node:os";
import type { CommandCategory, CommandRule, OwnershipLevel, PolicyFile, PolicyIssue } from "./types.ts";
import { canonicalPath, globToRegExp, isWithin, resolvePath } from "./path-utils.ts";

const DEFAULT_SECRET_PATTERNS = [
  "**/.env", "**/.env.*", "**/.npmrc", "**/.pypirc", "**/.netrc",
  "**/.git-credentials", "**/id_rsa", "**/id_ed25519", "**/id_ecdsa",
  "**/*.pem", "**/*.key", "**/*.p12", "**/*.pfx", "**/*.kdbx",
  "~/.ssh/**", "~/.aws/**", "~/.config/gcloud/**", "~/.kube/config",
  "~/.docker/config.json", "~/.config/gh/hosts.yml", "~/.pi/**/auth.json",
];

export type PolicyScope = "global" | "local";
interface LoadedPolicy { file: PolicyFile; path: string; base: string; scope: PolicyScope; }

export function emptyPolicy(): PolicyFile {
  return { version: 2, ownership: { edit: [], full: [] }, secrets: [], commands: [] };
}

function validateStrings(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new Error(`${field} must be an array of strings`);
  }
  return [...value];
}

function validatePolicy(value: unknown): PolicyFile {
  if (!value || typeof value !== "object") throw new Error("policy must be an object");
  const obj = value as Record<string, unknown>;
  if (obj.version !== 2) throw new Error("version must be 2; edit this policy manually (automatic migration is disabled)");
  if (!obj.ownership || typeof obj.ownership !== "object" || Array.isArray(obj.ownership)) {
    throw new Error("ownership must contain edit and full pattern lists");
  }
  const ownership = obj.ownership as Record<string, unknown>;
  const edit = validateStrings(ownership.edit, "ownership.edit");
  const full = validateStrings(ownership.full, "ownership.full");
  const secrets = validateStrings(obj.secrets, "secrets");
  const rawCommands = obj.commands ?? [];
  if (!Array.isArray(rawCommands)) throw new Error("commands must be an array");
  const categories = new Set<CommandCategory>(["allow", "read", "create", "edit", "delete", "execute", "remote", "deny"]);
  const commands = rawCommands.map((raw, index): CommandRule => {
    if (!raw || typeof raw !== "object") throw new Error(`commands[${index}] must be an object`);
    const rule = raw as Record<string, unknown>;
    if (typeof rule.name !== "string" || !categories.has(rule.category as CommandCategory)) {
      throw new Error(`commands[${index}] requires a name and valid category`);
    }
    return { name: rule.name, category: rule.category as CommandCategory, ...(typeof rule.note === "string" ? { note: rule.note } : {}) };
  });
  return { version: 2, ownership: { edit, full }, secrets, commands };
}

function parseOwnershipPattern(entry: string): { pattern: string; included: boolean } | undefined {
  let value = entry.trim();
  if (!value || value.startsWith("#")) return undefined;
  if (value.startsWith("\\!") || value.startsWith("\\#")) value = value.slice(1);
  else if (value.startsWith("!")) return { pattern: value.slice(1), included: false };
  return { pattern: value, included: true };
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
  private gitTrackedPaths = new Set<string>();

  constructor(extensionDir: string, cwd: string, home = homedir(), systemReadonlyRoots = ["/nix/store"]) {
    this.home = home;
    this.systemReadonlyRoots = systemReadonlyRoots.map(canonicalPath);
    this.globalPath = join(extensionDir, "policy.json");
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

  private includedIn(level: "edit" | "full", canonical: string): boolean {
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
    for (const root of [...this.transientRun, ...this.transientSession]) {
      if (isWithin(canonical, root)) return "edit";
    }
    if (this.includedIn("full", canonical)) return "full";
    if (this.gitTrackedPaths.has(canonical)) return "edit";
    if (this.includedIn("edit", canonical)) return "edit";
    return "read";
  }

  isSecret(path: string): boolean {
    const canonical = canonicalPath(path);
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

  commandCategory(name: string): CommandCategory | undefined {
    return this.policies.flatMap((policy) => policy.file.commands).findLast((rule) => rule.name === name)?.category;
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

  save(scope: PolicyScope, file: PolicyFile): void {
    this.write(scope, file);
  }

  ensurePolicy(scope: PolicyScope): string {
    const path = this.getPolicyPath(scope);
    if (!existsSync(path)) this.write(scope, emptyPolicy());
    return path;
  }

  appendOwnership(scope: PolicyScope, level: "edit" | "full", path: string): { path: string; line: number } {
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
}
