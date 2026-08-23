import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { GuardAnalyzer, splitShellCommandUnits } from "../analyzer.ts";
import { PolicyStore } from "../policy.ts";

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "bash-guard-analyzer-"));
  const extension = join(root, "extension");
  const workspace = join(root, "workspace");
  const home = join(root, "home");
  const systemReadonly = join(root, "nix", "store");
  const processDevice = join(root, "device");
  const processFds = join(root, "process-fds");
  mkdirSync(extension); mkdirSync(workspace); mkdirSync(home);
  mkdirSync(systemReadonly, { recursive: true }); mkdirSync(processDevice); mkdirSync(processFds);
  const policy = new PolicyStore(extension, workspace, home, [systemReadonly], { deviceRoot: processDevice, processFdRoot: processFds });
  return { root, workspace, systemReadonly, processDevice, processFds, policy, analyzer: new GuardAnalyzer(policy), cleanup: () => rmSync(root, { recursive: true, force: true }) };
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

test("process I/O redirections do not create ownership prompts", () => {
  const f = fixture();
  try {
    const config = join(f.workspace, "config");
    const data = join(f.workspace, "data");
    const sink = join(f.processDevice, "null");
    mkdirSync(config); mkdirSync(data);
    const command = `rg -n "stylua|--lsp" ${config} ${data} 2>${sink}`;
    assert.equal(f.analyzer.analyzeCommand(command, f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzePathAccess(sink, "edit", f.workspace, "write").decision, "allow");
    assert.equal(f.analyzer.analyzePathAccess(sink, "delete", f.workspace, "delete").decision, "deny");
    assert.equal(f.analyzer.analyzeCommand("printf value 2>&1", f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand("grep value <<< '.env'", f.workspace).decision, "allow");

    const ordinaryOutput = join(f.workspace, "existing.log");
    writeFileSync(ordinaryOutput, "old\n");
    assert.equal(f.analyzer.analyzeCommand(`printf value > ${ordinaryOutput}`, f.workspace).decision, "ask");
  } finally { f.cleanup(); }
});

test("system read-only roots allow reads and execution but deny mutation", () => {
  const f = fixture();
  try {
    const executable = join(f.systemReadonly, "printf");
    const unknownExecutable = join(f.systemReadonly, "unknown-tool");
    const absoluteCat = join(f.systemReadonly, "cat");
    const data = join(f.systemReadonly, "data.txt");
    const secret = join(f.systemReadonly, ".env");
    writeFileSync(executable, "#!/bin/sh\necho safe\n");
    writeFileSync(unknownExecutable, "#!/bin/sh\necho safe\n");
    writeFileSync(absoluteCat, "#!/bin/sh\necho safe\n");
    writeFileSync(data, "safe\n");
    writeFileSync(secret, "TOKEN=test\n");
    assert.equal(f.analyzer.analyzeCommand(executable, f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand(unknownExecutable, f.workspace).decision, "ask");
    assert.equal(f.analyzer.analyzeCommand(`${absoluteCat} ${secret}`, f.workspace).decision, "deny");
    assert.equal(f.analyzer.analyzeCommand(`cat ${data}`, f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand(`cat ${secret}`, f.workspace).decision, "deny");
    assert.equal(f.analyzer.analyzeCommand(`echo changed > ${data}`, f.workspace).decision, "deny");
    assert.equal(f.analyzer.analyzeCommand(`echo new > ${join(f.systemReadonly, "new.txt")}`, f.workspace).decision, "deny");
    assert.equal(f.analyzer.analyzeCommand(`rm ${data}`, f.workspace).decision, "deny");
  } finally { f.cleanup(); }
});

test("compound shell commands are separated in lexical permission order", () => {
  const f = fixture();
  try {
    const command = `echo "literal;value"; unknown-first && cat ${join(f.workspace, "missing.txt")} | unknown-second`;
    assert.deepEqual(splitShellCommandUnits(command), [
      'echo "literal;value"',
      "unknown-first",
      `cat ${join(f.workspace, "missing.txt")}`,
      "unknown-second",
    ]);
    const requiringPermission = f.analyzer.analyzeCommandUnits(command, f.workspace)
      .filter((unit) => unit.analysis.decision !== "allow");
    assert.deepEqual(requiringPermission.map((unit) => unit.command), ["unknown-first", "unknown-second"]);
    assert.match(requiringPermission[0]!.analysis.reasons.join(" "), /Unknown command unknown-first/);
    assert.match(requiringPermission[1]!.analysis.reasons.join(" "), /Unknown command unknown-second/);
  } finally { f.cleanup(); }
});

test("network diagnostics keep fd redirections attached and remain non-mutative", () => {
  const f = fixture();
  try {
    const output = join(f.workspace, "probe.out");
    const command = [
      "printf '%s\\n' '=== reachability ==='",
      "ping -c 2 -W 2 192.0.2.1 2>&1 || true",
      `for p in 80 631; do timeout 2 bash -c "true" > ${output} 2>&1 && echo "port $p open" || echo "port $p closed"; done`,
      "ipptool -tv ipp://192.0.2.1:631/ipp/print get-printer-attributes.test 2>&1 | tail -30 || true",
    ].join("\n");
    const units = splitShellCommandUnits(command);
    assert.equal(units.includes("1"), false);
    assert.equal(units.includes("2"), false);
    const requiringPermission = f.analyzer.analyzeCommandUnits(command, f.workspace)
      .filter((unit) => unit.analysis.decision !== "allow");
    assert.deepEqual(requiringPermission, []);
    assert.equal(
      f.analyzer.analyzeCommand("ipptool ipp://192.0.2.1/ipp/print print-job.test", f.workspace).decision,
      "ask",
    );
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
    const wildcard = f.analyzer.analyzeCommand("rm *.txt", f.workspace);
    assert.equal(wildcard.decision, "deny");
    assert.deepEqual(wildcard.trashablePaths, []);
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
    assert.equal(f.analyzer.analyzeCommand(`find ${f.workspace} -maxdepth 2 -type f -print`, f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand(`find ${f.workspace} -printf '%p\\n'`, f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand("find . -delete", f.workspace).decision, "deny");
    assert.equal(f.analyzer.analyzeCommand("find . -exec echo {} ;", f.workspace).decision, "ask");
    assert.equal(f.analyzer.analyzeCommand("find . -ok echo {} ;", f.workspace).decision, "ask");
  } finally { f.cleanup(); }
});

test("systemctl inspection and timeout wrappers preserve read-only classification", () => {
  const f = fixture();
  try {
    const readOnly = [
      "systemctl --user --no-pager --full status example.service",
      "systemctl --system --no-pager cat example.service",
      "systemctl --type service --state running --no-pager",
      "systemctl -p ActiveState --value show example.service",
      `timeout 5s find ${f.workspace} -maxdepth 1 -type f -print`,
      "timeout --foreground 5s systemctl --user status example.service",
      `timeout -k 1s 5s bash -lc "find ${f.workspace} -maxdepth 1 -print"`,
    ];
    for (const command of readOnly) {
      assert.equal(f.analyzer.analyzeCommand(command, f.workspace).decision, "allow", command);
    }
    assert.equal(f.analyzer.analyzeCommand("systemctl --user restart example.service", f.workspace).decision, "ask");
    assert.equal(f.analyzer.analyzeCommand("timeout 5s systemctl stop example.service", f.workspace).decision, "ask");
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
