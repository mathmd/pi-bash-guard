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

test("continued loop data is not treated as executable and curl GET remains read-only", () => {
  const f = fixture();
  try {
    const sink = join(f.processDevice, "null");
    const command = [
      "set -eu",
      "base=http://127.0.0.1:39000",
      "curl -fsS \"$base/resource/index\" | rg -n 'asset|config' | head",
      "for p in \\",
      "  /resource/a.css \\",
      "  /resource/a.js \\",
      "  /resource/plugin.js; do",
      `  code=$(curl -sS -o ${sink} -w '%{http_code}' "$base$p")`,
      "  printf '%s %s\\n' \"$code\" \"$p\"",
      "done",
    ].join("\n");
    const units = f.analyzer.analyzeCommandUnits(command, f.workspace);
    assert.deepEqual(units.filter((unit) => unit.analysis.decision !== "allow"), []);
    const header = units.find((unit) => unit.command.startsWith("for p in"))!;
    assert.deepEqual(header.analysis.accesses, []);

    assert.equal(f.analyzer.analyzeCommand("curl -X POST http://127.0.0.1/resource", f.workspace).decision, "ask");
    const existingOutput = join(f.workspace, "response.txt");
    writeFileSync(existingOutput, "old");
    const output = f.analyzer.analyzeCommand(`curl -o ${existingOutput} http://127.0.0.1/resource`, f.workspace);
    assert.equal(output.decision, "ask");
    assert.deepEqual(output.ownershipCandidates, [{ path: existingOutput, required: "edit" }]);
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

test("copy analysis expands prior assignments and checks concrete destination files", () => {
  const f = fixture();
  try {
    const source = join(f.systemReadonly, "package-assets");
    const destination = join(f.workspace, "generated-assets");
    mkdirSync(join(source, "plugins"), { recursive: true });
    mkdirSync(join(source, "fonts"));
    writeFileSync(join(source, "app.min.js"), "js");
    writeFileSync(join(source, "app.min.css"), "css");
    writeFileSync(join(source, "plugins", "plugin.min.js"), "plugin");
    writeFileSync(join(source, "fonts", "font.woff2"), "font");
    const command = [
      "set -eu",
      `src=${source}`,
      `dst=${destination}`,
      'mkdir -p "$dst/plugins"',
      'cp "$src/app.min.js" "$src/app.min.css" "$dst/"',
      'cp "$src/plugins/plugin.min.js" "$dst/plugins/"',
      'cp -R "$src/fonts" "$dst/"',
      'find "$dst" -type f | wc -l',
    ].join("\n");
    const units = f.analyzer.analyzeCommandUnits(command, f.workspace);
    assert.deepEqual(units.filter((unit) => unit.analysis.decision !== "allow"), []);
    const copyCreations = units.filter((unit) => unit.command.startsWith("cp "))
      .flatMap((unit) => unit.analysis.creationCandidates);
    assert.deepEqual(copyCreations, [
      join(destination, "app.min.js"),
      join(destination, "app.min.css"),
      join(destination, "plugins", "plugin.min.js"),
      join(destination, "fonts"),
      join(destination, "fonts", "font.woff2"),
    ]);
    assert.equal(copyCreations.includes(destination), false);

    mkdirSync(join(destination, "plugins"), { recursive: true });
    const existingTarget = join(destination, "plugins", "plugin.min.js");
    writeFileSync(existingTarget, "old");
    const overwrite = f.analyzer.analyzeCommandUnits([
      `src=${source}`,
      `dst=${destination}`,
      'cp "$src/plugins/plugin.min.js" "$dst/plugins/"',
    ].join("\n"), f.workspace).at(-1)!.analysis;
    assert.equal(overwrite.decision, "ask");
    assert.deepEqual(overwrite.ownershipCandidates, [{ path: existingTarget, required: "edit" }]);

    const existingFont = join(destination, "fonts", "font.woff2");
    mkdirSync(join(destination, "fonts"));
    writeFileSync(existingFont, "old-font");
    const recursiveOverwrite = f.analyzer.analyzeCommandUnits([
      `src=${source}`,
      `dst=${destination}`,
      'cp -R "$src/fonts" "$dst/"',
    ].join("\n"), f.workspace).at(-1)!.analysis;
    assert.equal(recursiveOverwrite.decision, "ask");
    assert.deepEqual(recursiveOverwrite.ownershipCandidates, [{ path: existingFont, required: "edit" }]);
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

test("execute ownership permits execution but not editing or deletion", () => {
  const f = fixture();
  try {
    const file = join(f.workspace, "execute-only.sh");
    writeFileSync(file, "echo safe\n");
    f.policy.save("local", {
      version: 3,
      ownership: { edit: [], execute: ["execute-only.sh"], full: [] },
      secrets: [],
      commands: { include: [], exclude: [] },
    });
    assert.equal(f.analyzer.analyzeCommand(`bash ${file}`, f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand(`touch ${file}`, f.workspace).decision, "ask");
    assert.equal(f.analyzer.analyzeCommand(`rm ${file}`, f.workspace).decision, "deny");
  } finally { f.cleanup(); }
});

test("full ownership permits screened script execution", () => {
  const f = fixture();
  try {
    const file = join(f.workspace, "trusted.sh");
    writeFileSync(file, "echo safe\n");
    f.policy.save("local", { version: 3, ownership: { edit: [], execute: [], full: ["trusted.sh"] }, secrets: [], commands: { include: [], exclude: [] } });
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
    f.policy.save("local", { version: 3, ownership: { edit: [], execute: [], full: ["bad.sh"] }, secrets: [], commands: { include: [], exclude: [] } });
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
    f.policy.save("local", { version: 3, ownership: { edit: [], execute: [], full: ["secret-reader.sh"] }, secrets: [], commands: { include: [], exclude: [] } });
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

test("embedded command strings are not inferred as paths", () => {
  const f = fixture();
  try {
    const generic = f.analyzer.analyzeCommand(`unknown-tool 'inspect("nested/example.so")'`, f.workspace);
    assert.equal(generic.decision, "ask");
    assert.deepEqual(generic.ownershipCandidates, []);
    assert.doesNotMatch(generic.reasons.join(" "), /Modification requires/);

    const embeddedCode = [
      "nvim --headless",
      `'+lua print(vim.inspect(vim.api.nvim_get_runtime_file("parser/example.so", true)))'`,
      "+qa",
    ].join(" ");
    const result = f.analyzer.analyzeCommand(embeddedCode, f.workspace);
    assert.equal(result.decision, "ask");
    assert.deepEqual(result.accesses, []);
    assert.deepEqual(result.ownershipCandidates, []);
    assert.deepEqual(result.reasons, ["Unknown command nvim requires approval"]);
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

test("command existence inspection does not execute unresolved loop values", () => {
  const f = fixture();
  try {
    assert.equal(f.analyzer.analyzeCommand(`command -v "$c"`, f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand(`command -pv "$c"`, f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand(`command -V -- "$c"`, f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand(`command "$c"`, f.workspace).decision, "ask");
    assert.equal(f.analyzer.analyzeCommand(`command -p "$c"`, f.workspace).decision, "ask");

    const loop = `for c in nix nh nixos-rebuild treefmt nixfmt shfmt statix deadnix shellcheck; do printf '%-16s' "$c"; command -v "$c" || true; done`;
    const units = f.analyzer.analyzeCommandUnits(loop, f.workspace);
    assert.equal(units.length > 0, true);
    for (const unit of units) assert.equal(unit.analysis.decision, "allow", unit.command);
  } finally { f.cleanup(); }
});

test("literal executable variables are analyzed and surfaced per candidate", () => {
  const f = fixture();
  try {
    const loop = `for c in echo unknown-one unknown-two; do "$c" --version; done`;
    const requiring = f.analyzer.analyzeCommandUnits(loop, f.workspace)
      .filter((unit) => unit.analysis.decision !== "allow");
    assert.deepEqual(requiring.map((unit) => unit.executableBindings), [
      [{ name: "c", value: "unknown-one" }],
      [{ name: "c", value: "unknown-two" }],
    ]);
    assert.match(requiring[0]!.analysis.reasons.join(" "), /Unknown command unknown-one/);
    assert.match(requiring[1]!.analysis.reasons.join(" "), /Unknown command unknown-two/);

    const assigned = f.analyzer.analyzeCommandUnits(`c=assigned-tool; "$c"`, f.workspace)
      .filter((unit) => unit.analysis.decision !== "allow");
    assert.deepEqual(assigned[0]?.executableBindings, [{ name: "c", value: "assigned-tool" }]);

    const dynamic = f.analyzer.analyzeCommandUnits(`"$runtime_tool" --version`, f.workspace)
      .filter((unit) => unit.analysis.decision !== "allow");
    assert.deepEqual(dynamic[0]?.executableBindings, [{ name: "runtime_tool" }]);
    assert.match(dynamic[0]?.analysis.reasons.join(" ") ?? "", /cannot be resolved statically/);

    const dynamicAssignment = f.analyzer.analyzeCommandUnits(`c=$runtime_tool; "$c"`, f.workspace)
      .filter((unit) => unit.analysis.decision !== "allow");
    assert.deepEqual(dynamicAssignment[0]?.executableBindings, [{ name: "c" }]);
    assert.match(dynamicAssignment[0]?.analysis.reasons.join(" ") ?? "", /\$c cannot be resolved statically/);

    const expandedLoop = f.analyzer.analyzeCommandUnits(`tools="one two"; for c in $tools; do "$c"; done`, f.workspace)
      .filter((unit) => unit.analysis.decision !== "allow");
    assert.deepEqual(expandedLoop[0]?.executableBindings, [{ name: "c" }]);
    assert.match(expandedLoop[0]?.analysis.reasons.join(" ") ?? "", /\$c cannot be resolved statically/);
  } finally { f.cleanup(); }
});

test("non-shell inline interpreters are opaque rather than parsed as shell", () => {
  const f = fixture();
  try {
    const grouped = `for p in "${f.workspace}"; do (cd "$p" && node -e 'console.log(\`cwd: \${process.cwd()}\`)'); done`;
    const requiring = f.analyzer.analyzeCommandUnits(grouped, f.workspace)
      .filter((unit) => unit.analysis.decision !== "allow");
    assert.equal(requiring.length, 1);
    assert.deepEqual(requiring[0]?.analysis.reasons, ["Opaque node inline code requires approval"]);

    assert.equal(f.analyzer.analyzeCommand(`bash -lc "printf safe"`, f.workspace).decision, "allow");
    for (const command of [
      `node --eval 'console.log("safe")'`,
      `python -c 'print("safe")'`,
      `ruby -e 'puts "safe"'`,
      `perl -e 'print "safe"'`,
      `deno eval 'console.log("safe")'`,
      `bun -e 'console.log("safe")'`,
    ]) {
      const result = f.analyzer.analyzeCommand(command, f.workspace);
      assert.equal(result.decision, "ask", command);
      assert.match(result.reasons.join(" "), /Opaque .* inline code requires approval/, command);
      assert.doesNotMatch(result.reasons.join(" "), /Shell syntax could not be analyzed/, command);
    }
    const nodeScript = join(f.workspace, "runner.js");
    writeFileSync(nodeScript, "console.log('safe')\n");
    const scriptWithFlag = f.analyzer.analyzeCommand(`node ${nodeScript} -p config.json`, f.workspace);
    assert.equal(scriptWithFlag.decision, "ask");
    assert.doesNotMatch(scriptWithFlag.reasons.join(" "), /Opaque node inline code/);
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

test("trusted command patterns override unknown fallback only when arguments match", () => {
  const f = fixture();
  try {
    f.policy.save("local", {
      version: 3,
      ownership: { edit: [], execute: [], full: [] },
      secrets: [],
      commands: {
        include: [
          ["safe-local"],
          ["inspect-*", "--json", "**"],
          ["unordered", "one", "two"],
        ],
        exclude: [["inspect-*", "--write", "**"]],
      },
    });
    assert.equal(f.analyzer.analyzeCommand("safe-local", f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand("safe-local extra", f.workspace).decision, "ask");
    assert.equal(f.analyzer.analyzeCommand("inspect-local file --json", f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand("inspect-local --write --json", f.workspace).decision, "ask");
    assert.equal(f.analyzer.analyzeCommand("unordered two one", f.workspace).decision, "allow");

    const pathArgument = join(f.workspace, "input.txt");
    writeFileSync(pathArgument, "input\n");
    const guardedPath = f.analyzer.analyzeCommand(`inspect-local --json ${pathArgument}`, f.workspace);
    assert.equal(guardedPath.decision, "ask");
    assert.deepEqual(guardedPath.ownershipCandidates, [{ path: pathArgument, required: "edit" }]);
    f.policy.addCreated(pathArgument);
    assert.equal(f.analyzer.analyzeCommand(`inspect-local ${pathArgument} --json`, f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand(`inspect-local --json ${join(f.workspace, ".env")}`, f.workspace).decision, "deny");
    assert.equal(f.analyzer.analyzeCommand(`inspect-local --json ${join(f.workspace, ".git", "config")}`, f.workspace).decision, "deny");

    f.policy.save("local", {
      version: 3,
      ownership: { edit: [], execute: [], full: [] },
      secrets: [],
      commands: { include: [["*", "**"]], exclude: [] },
    });
    assert.equal(f.analyzer.analyzeCommand("anything --any-flag", f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand("git reset --hard HEAD", f.workspace).decision, "deny");
  } finally { f.cleanup(); }
});
