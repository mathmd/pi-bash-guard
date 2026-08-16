import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { GuardAnalyzer } from "../analyzer.ts";
import { PolicyStore } from "../policy.ts";

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "bash-guard-analyzer-"));
  const extension = join(root, "extension");
  const workspace = join(root, "workspace");
  const home = join(root, "home");
  mkdirSync(extension); mkdirSync(workspace); mkdirSync(home);
  const policy = new PolicyStore(extension, workspace, home);
  return { root, workspace, policy, analyzer: new GuardAnalyzer(policy), cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

test("read-only command is allowed but secret read is denied", () => {
  const f = fixture();
  try {
    const plain = join(f.workspace, "plain.txt");
    const secret = join(f.workspace, ".env");
    writeFileSync(plain, "plain"); writeFileSync(secret, "SECRET=test");
    assert.equal(f.analyzer.analyzeCommand(`cat ${plain}`, f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand(`cat ${secret}`, f.workspace).decision, "deny");
  } finally { f.cleanup(); }
});

test("new creation is allowed and an existing unowned edit asks", () => {
  const f = fixture();
  try {
    const fresh = join(f.workspace, "fresh.txt");
    const existing = join(f.workspace, "existing.txt");
    writeFileSync(existing, "old");
    const create = f.analyzer.analyzeCommand(`touch ${fresh}`, f.workspace);
    assert.equal(create.decision, "allow");
    assert.deepEqual(create.creationCandidates, [fresh]);
    assert.equal(f.analyzer.analyzeCommand(`touch ${existing}`, f.workspace).decision, "ask");
  } finally { f.cleanup(); }
});

test("edit ownership permits editing and deletion but still asks execution", () => {
  const f = fixture();
  try {
    const file = join(f.workspace, "owned.sh");
    writeFileSync(file, "echo safe\n");
    f.policy.addCreated(file);
    assert.equal(f.analyzer.analyzeCommand(`touch ${file}`, f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand(`rm ${file}`, f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand(`bash ${file}`, f.workspace).decision, "ask");
  } finally { f.cleanup(); }
});

test("full ownership permits screened script execution", () => {
  const f = fixture();
  try {
    const file = join(f.workspace, "trusted.sh");
    writeFileSync(file, "echo safe\n");
    f.policy.save("local", { version: 2, ownership: { edit: [], full: ["trusted.sh"] }, secrets: [], commands: [] });
    assert.equal(f.analyzer.analyzeCommand(`bash ${file}`, f.workspace).decision, "allow");
  } finally { f.cleanup(); }
});

test("unowned deletion is denied and exposes literal trash targets", () => {
  const f = fixture();
  try {
    const file = join(f.workspace, "old.txt");
    writeFileSync(file, "old");
    const result = f.analyzer.analyzeCommand(`rm ${file}`, f.workspace);
    assert.equal(result.decision, "deny");
    assert.deepEqual(result.trashablePaths, [file]);
  } finally { f.cleanup(); }
});

test("all pipeline segments are analyzed", () => {
  const f = fixture();
  try {
    const file = join(f.workspace, "pipeline-target.txt");
    writeFileSync(file, "old");
    const result = f.analyzer.analyzeCommand(`echo ok | rm ${file}`, f.workspace);
    assert.equal(result.decision, "deny");
    assert.match(result.reasons.join(" "), /deletion/);
  } finally { f.cleanup(); }
});

test("Git read operations allow, mutations ask, and forced push denies", () => {
  const f = fixture();
  try {
    writeFileSync(join(f.workspace, ".env"), "TOKEN=test\n");
    const readOnly = [
      "git status --short --ignored",
      `git -C ${f.workspace} status`,
      `git -C ${f.workspace} log -1 --oneline`,
      `git -C ${f.workspace} diff --check`,
      "git branch --contains main",
      "git tag --list",
      "git remote show origin",
      "git config user.name",
      `git config --file ${join(f.workspace, "config")} --get user.name`,
      "git stash list",
      "git worktree list",
      "git reflog show",
      "git fsck",
    ];
    for (const command of readOnly) assert.equal(f.analyzer.analyzeCommand(command, f.workspace).decision, "allow", command);

    const mutative = [
      "git commit -m test",
      "git branch feature",
      "git tag v1",
      "git remote add origin example.invalid/repo",
      "git config user.name Changed",
      "git stash",
      "git worktree add ../copy",
      "git cherry-pick HEAD",
      `git diff --output=${join(f.workspace, "changes.patch")}`,
    ];
    for (const command of mutative) assert.equal(f.analyzer.analyzeCommand(command, f.workspace).decision, "ask", command);

    assert.equal(f.analyzer.analyzeCommand("git show HEAD:.env", f.workspace).decision, "deny");
    assert.equal(f.analyzer.analyzeCommand("git log -- .env", f.workspace).decision, "deny");
    assert.equal(f.analyzer.analyzeCommand("git push --force origin main", f.workspace).decision, "deny");
    assert.equal(f.analyzer.analyzeCommand(`git -C ${f.workspace} push --force-with-lease origin main`, f.workspace).decision, "deny");
    assert.equal(f.analyzer.analyzeCommand(`git -C ${f.workspace} reset --hard HEAD`, f.workspace).decision, "deny");
  } finally { f.cleanup(); }
});

test("catastrophic content in a script is denied even with full ownership", () => {
  const f = fixture();
  try {
    const script = join(f.workspace, "bad.sh");
    writeFileSync(script, "#!/bin/sh\nmkfs /dev/example\n");
    f.policy.save("local", { version: 2, ownership: { edit: [], full: ["bad.sh"] }, secrets: [], commands: [] });
    assert.equal(f.analyzer.analyzeCommand(`bash ${script}`, f.workspace).decision, "deny");
  } finally { f.cleanup(); }
});

test("explicit secret references in a full-owned script are denied", () => {
  const f = fixture();
  try {
    const secret = join(f.workspace, ".env");
    const script = join(f.workspace, "secret-reader.sh");
    writeFileSync(secret, "TOKEN=test\n");
    writeFileSync(script, `#!/bin/sh\ncat ${secret}\n`);
    f.policy.save("local", { version: 2, ownership: { edit: [], full: ["secret-reader.sh"] }, secrets: [], commands: [] });
    assert.equal(f.analyzer.analyzeCommand(`bash ${script}`, f.workspace).decision, "deny");
  } finally { f.cleanup(); }
});

test("direct .git writes deny while new ordinary redirection is attributable", () => {
  const f = fixture();
  try {
    mkdirSync(join(f.workspace, ".git"));
    const gitConfig = join(f.workspace, ".git", "config");
    writeFileSync(gitConfig, "old");
    assert.equal(f.analyzer.analyzeCommand(`echo x > ${gitConfig}`, f.workspace).decision, "deny");
    const fresh = join(f.workspace, "output.txt");
    const result = f.analyzer.analyzeCommand(`echo x > ${fresh}`, f.workspace);
    assert.equal(result.decision, "allow");
    assert.deepEqual(result.creationCandidates, [fresh]);
  } finally { f.cleanup(); }
});

test("find mutation is not mistaken for a read-only search", () => {
  const f = fixture();
  try {
    assert.equal(f.analyzer.analyzeCommand("find . -delete", f.workspace).decision, "deny");
    assert.equal(f.analyzer.analyzeCommand("find . -exec echo {} ;", f.workspace).decision, "ask");
  } finally { f.cleanup(); }
});

test("creating a new policy or .git file is not silently allowed", () => {
  const f = fixture();
  try {
    const policyPath = f.policy.getLocalPath();
    const gitPath = join(f.workspace, ".git", "new-config");
    assert.equal(f.analyzer.analyzeCommand(`echo x > ${policyPath}`, f.workspace).decision, "ask");
    assert.equal(f.analyzer.analyzeCommand(`echo x > ${gitPath}`, f.workspace).decision, "deny");
  } finally { f.cleanup(); }
});

test("common shell grammar and builtins are recognized", () => {
  const f = fixture();
  try {
    assert.equal(f.analyzer.analyzeCommand(`cd ${f.workspace}`, f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand("exit 0", f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand("set -e", f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand("{ echo safe; }", f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand("if true; then echo safe; fi", f.workspace).decision, "allow");
  } finally { f.cleanup(); }
});

test("tee creates new files but asks before editing existing files", () => {
  const f = fixture();
  try {
    const fresh = join(f.workspace, "tee-new.txt");
    const existing = join(f.workspace, "tee-existing.txt");
    writeFileSync(existing, "old");
    const created = f.analyzer.analyzeCommand(`printf value | tee ${fresh}`, f.workspace);
    assert.equal(created.decision, "allow");
    assert.deepEqual(created.creationCandidates, [fresh]);
    assert.equal(f.analyzer.analyzeCommand(`if true; then tee ${existing}; fi`, f.workspace).decision, "ask");
  } finally { f.cleanup(); }
});

test("custom command registration overrides unknown-command fallback", () => {
  const f = fixture();
  try {
    f.policy.save("local", {
      version: 2,
      ownership: { edit: [], full: [] },
      secrets: [],
      commands: [
        { name: "inspect-local", category: "read" },
        { name: "safe-local", category: "allow" },
        { name: "forbidden-local", category: "deny" },
      ],
    });
    assert.equal(f.analyzer.analyzeCommand("safe-local", f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand("inspect-local", f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand("forbidden-local", f.workspace).decision, "deny");
  } finally { f.cleanup(); }
});
