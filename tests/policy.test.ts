import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { parsePermissionTimeout, PolicyStore } from "../policy.ts";

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "bash-guard-policy-"));
  const extension = join(root, "extension");
  const workspace = join(root, "workspace");
  const home = join(root, "home");
  mkdirSync(extension); mkdirSync(workspace); mkdirSync(home);
  const policy = new PolicyStore(extension, workspace, home);
  return { root, extension, workspace, home, policy, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

test("ordered ownership patterns form edit, execute, and full capabilities", () => {
  const f = fixture();
  try {
    const full = join(f.workspace, "generated", "full.txt");
    const edit = join(f.workspace, "generated", "edit-only", "edit.txt");
    const execute = join(f.workspace, "generated", "execute-only", "run.sh");
    const read = join(f.workspace, "generated", "readonly", "read.txt");
    f.policy.save("local", {
      version: 3,
      ownership: {
        edit: ["generated/**", "!generated/execute-only/**", "!generated/readonly/**"],
        execute: ["generated/**", "!generated/edit-only/**", "!generated/readonly/**"],
        full: ["generated/**", "!generated/edit-only/**", "!generated/execute-only/**", "!generated/readonly/**"],
      },
      secrets: [],
      commands: { include: [], exclude: [] },
    });
    assert.equal(f.policy.ownership(full), "full");
    assert.equal(f.policy.ownership(edit), "edit");
    assert.equal(f.policy.ownership(execute), "execute");
    assert.equal(f.policy.ownership(read), "read");
  } finally { f.cleanup(); }
});

test("curated and custom secrets are recognized inside fixture", () => {
  const f = fixture();
  try {
    const env = join(f.workspace, ".env");
    const custom = join(f.workspace, "private", "token.txt");
    f.policy.save("local", { version: 3, ownership: { edit: [], execute: [], full: [] }, secrets: ["private/**"], commands: { include: [], exclude: [] } });
    assert.equal(f.policy.isSecret(env), true);
    assert.equal(f.policy.isSecret(custom), true);
    assert.equal(f.policy.isSecret(join(f.workspace, "public.txt")), false);
  } finally { f.cleanup(); }
});

test("created paths under the isolated /tmp fixture have session edit ownership", () => {
  const f = fixture();
  try {
    const created = join(f.workspace, "created", "child.txt");
    mkdirSync(join(f.workspace, "created"));
    writeFileSync(created, "x");
    f.policy.addCreated(join(f.workspace, "created"));
    assert.equal(f.policy.ownership(created), "edit");
    f.policy.clearRunOwnership();
    assert.equal(f.policy.ownership(created), "edit");
    f.policy.clearSessionOwnership();
    assert.equal(f.policy.ownership(created), "read");
  } finally { f.cleanup(); }
});

test("global and local policy paths are always protected", () => {
  const f = fixture();
  try {
    assert.equal(f.policy.isPolicyPath(f.policy.globalPath), true);
    assert.equal(f.policy.isPolicyPath(f.policy.getLocalPath()), true);
  } finally { f.cleanup(); }
});

test("ownership append writes the exact path and reports its editor line", () => {
  const f = fixture();
  try {
    const target = join(f.workspace, "existing.txt");
    writeFileSync(target, "x");
    const result = f.policy.appendOwnership("local", "edit", target);
    const lines = readFileSync(result.path, "utf8").split("\n");
    assert.equal(lines[result.line - 1]?.includes(JSON.stringify(target)), true);
    assert.equal(f.policy.ownership(target), "edit");
  } finally { f.cleanup(); }
});

test("read-only tool lists combine and append at an editor-targetable line", () => {
  const f = fixture();
  try {
    f.policy.save("global", {
      version: 3,
      ownership: { edit: [], execute: [], full: [] },
      secrets: [],
      commands: { include: [], exclude: [] },
      tools: { read: ["anchor_grep"] },
    });
    f.policy.save("local", { version: 3, ownership: { edit: [], execute: [], full: [] }, secrets: [], commands: { include: [], exclude: [] } });
    assert.equal(f.policy.isReadOnlyTool("anchor_grep"), true);
    assert.equal(f.policy.isReadOnlyTool("unknown_tool"), false);

    const result = f.policy.appendReadOnlyTool("local", "source_check");
    const lines = readFileSync(result.path, "utf8").split("\n");
    assert.equal(lines[result.line - 1]?.includes(JSON.stringify("source_check")), true);
    assert.equal(f.policy.isReadOnlyTool("source_check"), true);
  } finally { f.cleanup(); }
});

test("trusted command append is exact, escaped, unordered, and editor-targetable", () => {
  const f = fixture();
  try {
    const result = f.policy.appendTrustedCommand("local", "inspect*", ["two", "one?", "**"]);
    const written = JSON.parse(readFileSync(result.path, "utf8")) as { commands: { include: string[][] } };
    assert.deepEqual(written.commands.include, [["inspect\\*", "two", "one\\?", "\\*\\*"]]);
    const lines = readFileSync(result.path, "utf8").split("\n");
    assert.equal(lines[result.line - 1]?.includes("inspect"), true);
    assert.equal(f.policy.isTrustedCommand("inspect*", ["**", "one?", "two"]), true);
    assert.equal(f.policy.isTrustedCommand("inspect-anything", ["**", "one?", "two"]), false);
    assert.equal(f.policy.isTrustedCommand("inspect*", ["one?", "two", "extra"]), false);
  } finally { f.cleanup(); }
});

test("permission timeout accepts durations and trusted local policy overrides global", () => {
  const f = fixture();
  try {
    assert.equal(parsePermissionTimeout("1m30s"), 90_000);
    assert.equal(parsePermissionTimeout("45s"), 45_000);
    assert.equal(parsePermissionTimeout(0), 0);
    assert.throws(() => parsePermissionTimeout("soon"), /permissionTimeout/);

    f.policy.save("global", {
      version: 3,
      ownership: { edit: [], execute: [], full: [] },
      secrets: [],
      commands: { include: [], exclude: [] },
      permissionTimeout: "2m",
    });
    assert.equal(f.policy.permissionTimeoutMs(), 120_000);
    f.policy.save("local", {
      version: 3,
      ownership: { edit: [], execute: [], full: [] },
      secrets: [],
      commands: { include: [], exclude: [] },
      permissionTimeout: "15s",
    });
    assert.equal(f.policy.permissionTimeoutMs(), 15_000);
  } finally { f.cleanup(); }
});

test("older policy versions are rejected without migration or rewrite", () => {
  const f = fixture();
  try {
    const path = f.policy.getLocalPath();
    mkdirSync(join(f.workspace, ".pi"));
    const original = '{"version":2,"ownership":{"edit":[],"full":[]},"secrets":[],"commands":[]}\n';
    writeFileSync(path, original);
    f.policy.reload();
    assert.match(f.policy.getIssues()[0]?.message ?? "", /version must be 3/);
    assert.equal(readFileSync(path, "utf8"), original);
  } finally { f.cleanup(); }
});

test("Gitignore-style basename and trailing-directory patterns match", () => {
  const f = fixture();
  try {
    f.policy.save("local", {
      version: 3,
      ownership: { edit: ["cache/", "*.generated"], execute: [], full: [] },
      secrets: [],
      commands: { include: [], exclude: [] },
    });
    assert.equal(f.policy.ownership(join(f.workspace, "cache")), "edit");
    assert.equal(f.policy.ownership(join(f.workspace, "cache", "nested.txt")), "edit");
    assert.equal(f.policy.ownership(join(f.workspace, "deep", "value.generated")), "edit");
  } finally { f.cleanup(); }
});

test("Git-tracked files receive automatic edit ownership", () => {
  const f = fixture();
  try {
    const tracked = join(f.workspace, "tracked.txt");
    const untracked = join(f.workspace, "untracked.txt");
    writeFileSync(tracked, "tracked\n");
    writeFileSync(untracked, "untracked\n");
    assert.equal(spawnSync("git", ["-C", f.workspace, "init", "--quiet"]).status, 0);
    assert.equal(spawnSync("git", ["-C", f.workspace, "add", "--", tracked]).status, 0);
    f.policy.refreshGitOwnership();
    assert.equal(f.policy.ownership(tracked), "edit");
    assert.equal(f.policy.ownership(untracked), "read");

    rmSync(tracked);
    f.policy.refreshGitOwnership();
    assert.equal(f.policy.ownership(tracked), "edit");
  } finally { f.cleanup(); }
});

test("Git ownership discovery follows repository ancestors and cwd symlinks", () => {
  const f = fixture();
  try {
    const nested = join(f.workspace, "packages", "app");
    const tracked = join(nested, "tracked.txt");
    mkdirSync(nested, { recursive: true });
    writeFileSync(tracked, "tracked\n");
    assert.equal(spawnSync("git", ["-C", f.workspace, "init", "--quiet"]).status, 0);
    assert.equal(spawnSync("git", ["-C", f.workspace, "add", "--", tracked]).status, 0);

    const nestedPolicy = new PolicyStore(f.extension, nested, f.home);
    assert.equal(nestedPolicy.ownership(tracked), "edit");

    const linkedCwd = join(f.root, "linked-workdir");
    symlinkSync(nested, linkedCwd, "dir");
    const linkedPolicy = new PolicyStore(f.extension, linkedCwd, f.home);
    assert.equal(linkedPolicy.ownership(join(linkedCwd, "tracked.txt")), "edit");
    assert.equal(linkedPolicy.getLocalPath(), join(nested, ".pi", "bash-guard.json"));
  } finally { f.cleanup(); }
});
