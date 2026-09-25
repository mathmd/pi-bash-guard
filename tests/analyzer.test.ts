import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
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

test("shell assignments propagate literal and runtime-generated paths", () => {
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

    const runtimeUnits = f.analyzer.analyzeCommandUnits([
      "tmp=$(mktemp -d)",
      "trap 'rm -rf \"$tmp\"' EXIT",
      "git clone https://example.invalid/repo.git \"$tmp/repo\"",
      "git -C \"$tmp/repo\" sparse-checkout init --cone",
      "rg needle \"$tmp/repo/src\"",
    ].join("; "), f.workspace);
    assert.deepEqual(runtimeUnits[0]?.analysis.creationPatterns, ["/tmp/tmp.*"]);
    assert.equal(runtimeUnits.find((unit) => unit.command.startsWith("trap "))?.analysis.decision, "allow");
    assert.equal(runtimeUnits.find((unit) => unit.command.startsWith("rg "))?.analysis.decision, "allow");
    assert.equal(runtimeUnits.find((unit) => unit.command.startsWith("git clone"))?.analysis.decision, "allow");
    const runtimePrompts = runtimeUnits.filter((unit) => unit.analysis.decision !== "allow");
    assert.deepEqual(runtimePrompts.map((unit) => unit.analysis.reasons), [
      ["Mutative or unknown Git operation (sparse-checkout) requires approval"],
    ]);
    assert.equal(runtimePrompts.some((unit) => unit.analysis.reasons.some((reason) => reason.includes("Dynamic path"))), false);
    for (const unit of runtimePrompts) {
      const tmpBinding = unit.resolvedBindings?.find(({ name }) => name === "tmp");
      assert.equal(tmpBinding?.symbolic, "runtime directory created by mktemp under /tmp");
      assert.match(tmpBinding?.value ?? "", /^\/tmp\/\.bash-guard-mktemp-tmp-/);
    }

    const pidUnits = f.analyzer.analyzeCommandUnits([
      "repo=/tmp/hyprland-research-$$",
      "git clone https://example.invalid/repo.git \"$repo\"",
      "cd \"$repo\"",
      "git show -s --format=%H",
      "rg needle \"$repo/src\"",
    ].join("; "), f.workspace);
    assert.equal(pidUnits.every((unit) => unit.analysis.decision === "allow"), true);
    const pidClone = pidUnits.find((unit) => unit.command.startsWith("git clone"));
    assert.deepEqual(pidClone?.analysis.creationPatterns, ["/tmp/hyprland-research-[0-9]*"]);
    const repoBinding = pidClone?.resolvedBindings?.find(({ name }) => name === "repo");
    assert.equal(repoBinding?.symbolic, "runtime path /tmp/hyprland-research-<shell-pid>");
    assert.equal(pidUnits.some((unit) => unit.analysis.reasons.some((reason) => reason.includes("Dynamic path"))), false);
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
    const directory = join(f.workspace, "owned-directory");
    mkdirSync(directory);
    writeFileSync(join(directory, "child"), "safe\n");
    f.policy.addCreated(directory);
    assert.equal(f.analyzer.analyzeCommand(`rm -rf ${directory}`, f.workspace).decision, "allow");
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
    assert.deepEqual(wildcard.trashablePaths, [file]);
    assert.deepEqual(wildcard.pathExpansions, [{ expression: "*.txt", matches: [file] }]);
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

    const cloneTarget = join(f.workspace, "fresh-clone");
    const clone = f.analyzer.analyzeCommand(`git clone https://example.invalid/repo.git ${cloneTarget}`, f.workspace);
    assert.equal(clone.decision, "allow");
    assert.deepEqual(clone.creationCandidates, [cloneTarget]);
    assert.equal(
      f.analyzer.analyzeCommand(`git clone ${join(f.workspace, ".env")} ${join(f.workspace, "secret-clone")}`, f.workspace).decision,
      "deny",
    );
    mkdirSync(join(f.workspace, "existing-clone"));
    assert.equal(
      f.analyzer.analyzeCommand(`git clone https://example.invalid/repo.git ${join(f.workspace, "existing-clone")}`, f.workspace).decision,
      "ask",
    );
    assert.equal(f.analyzer.analyzeCommand("git show HEAD:.env", f.workspace).decision, "deny");
    assert.equal(f.analyzer.analyzeCommand("git log -- .env", f.workspace).decision, "deny");
    assert.equal(f.analyzer.analyzeCommand("git push --force origin main", f.workspace).decision, "deny");
    assert.equal(f.analyzer.analyzeCommand(`git -C ${f.workspace} push --force-with-lease origin main`, f.workspace).decision, "deny");
    assert.equal(f.analyzer.analyzeCommand(`git -C ${f.workspace} reset --hard HEAD`, f.workspace).decision, "deny");
  } finally { f.cleanup(); }
});

test("catastrophic screening distinguishes executable commands from fixture data", () => {
  const f = fixture();
  try {
    const badShell = join(f.workspace, "bad.sh");
    const dataShell = join(f.workspace, "data.sh");
    const safeTest = join(f.workspace, "safe.test.ts");
    const dangerousTest = join(f.workspace, "dangerous.test.ts");
    writeFileSync(badShell, "#!/bin/sh\nmkfs /dev/example\n");
    writeFileSync(dataShell, "#!/bin/sh\nprintf '%s\\n' 'mkfs /dev/example'\n");
    writeFileSync(safeTest, [
      'import assert from "node:assert/strict";',
      'import { execSync } from "node:child_process";',
      'const fixture = "git push --force origin main";',
      'const secretFixture = "\\x2f.env";',
      'execSync(`printf "%s\\n" "${fixture}"`);',
      'assert.equal(fixture.includes("--force"), true);',
    ].join("\n"));
    f.policy.save("local", {
      version: 3,
      ownership: { edit: [], execute: [], full: ["bad.sh", "data.sh", "*.test.ts"] },
      secrets: [],
      commands: { include: [], exclude: [] },
    });

    for (const command of [
      "dd if=input of=/dev/example",
      "shutdown now",
      "env MODE=test git push --force origin main",
      "terraform destroy -auto-approve",
      "rm /",
      ":(){ :|:& };:",
    ]) assert.equal(f.analyzer.analyzeCommand(command, f.workspace).decision, "deny", command);
    assert.equal(f.analyzer.analyzeCommand(`bash ${badShell}`, f.workspace).decision, "deny");
    assert.equal(f.analyzer.analyzeCommand(`bash ${dataShell}`, f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand(`printf '%s\\n' 'git push --force origin main'`, f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand(`printf '%s\\n' ':(){ :|:& };:'`, f.workspace).decision, "allow");
    const inertSecret = "/" + ".env";
    assert.equal(f.analyzer.analyzeCommand(`printf '%s\\n' '${inertSecret}'`, f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand(`node -e 'console.log("${inertSecret}")'`, f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand(`python -c 'print("${inertSecret}")'`, f.workspace).decision, "allow");
    const inlineData = f.analyzer.analyzeCommand(`node -e 'console.log("git push --force origin main")'`, f.workspace);
    assert.equal(inlineData.decision, "allow");
    assert.deepEqual(inlineData.reasons, []);
    assert.equal(
      f.analyzer.analyzeCommand(`python -c 'import os; os.system("git push --force origin main")'`, f.workspace).decision,
      "deny",
    );
    assert.equal(
      f.analyzer.analyzeCommand(`node --test --eval 'console.log("safe")'`, f.workspace).decision,
      "allow",
    );
    const unresolvedTests = f.analyzer.analyzeCommand('node --test "$runtime"', f.workspace);
    assert.equal(unresolvedTests.decision, "ask");
    assert.match(unresolvedTests.reasons.join(" "), /could not be discovered safely/);

    const explicitTests = f.analyzer.analyzeCommand(`node --test ${safeTest}`, f.workspace);
    assert.equal(explicitTests.decision, "allow");
    assert.deepEqual(explicitTests.accesses.map((access) => access.path), [safeTest]);
    assert.equal(f.analyzer.analyzeCommand("node --test", f.workspace).decision, "allow");
    const afterCd = f.analyzer.analyzeCommandUnits(`cd ${f.workspace} && node --test safe.test.ts`, f.root);
    assert.equal(afterCd.at(-1)?.analysis.decision, "allow");
    assert.deepEqual(afterCd.at(-1)?.analysis.accesses.map((access) => access.path), [safeTest]);

    writeFileSync(dangerousTest, [
      'import { execSync } from "node:child_process";',
      'execSync("git push --force origin main");',
    ].join("\n"));
    const dangerous = f.analyzer.analyzeCommand(`node --test ${dangerousTest}`, f.workspace);
    assert.equal(dangerous.decision, "deny");
    assert.match(dangerous.reasons.join(" "), /Destructive Git operation|forced remote history rewrite/);

    const invalidTest = join(f.workspace, "invalid.test.ts");
    writeFileSync(invalidTest, "const broken = ;\n");
    const invalid = f.analyzer.analyzeCommand(`node --test ${invalidTest}`, f.workspace);
    assert.equal(invalid.decision, "ask");
    assert.match(invalid.reasons.join(" "), /could not be inspected safely/);
  } finally { f.cleanup(); }
});
test("script and inline source mutations require target ownership", () => {
  const f = fixture();
  try {
    const target = join(f.workspace, "unowned.txt");
    const owned = join(f.workspace, "owned.txt");
    const shellScript = join(f.workspace, "mutate.sh");
    const nodeScript = join(f.workspace, "mutate.mjs");
    const pythonScript = join(f.workspace, "mutate.py");
    const executeScript = join(f.workspace, "execute.mjs");
    const helper = join(f.workspace, "helper.sh");
    const pythonImportScript = join(f.workspace, "imports.py");
    const pythonHelper = join(f.workspace, "local_helper.py");
    const nodeImportScript = join(f.workspace, "imports.mjs");
    const nodeHelper = join(f.workspace, "local-helper.mjs");
    const dynamicShellScript = join(f.workspace, "dynamic.sh");
    const dynamicNodeScript = join(f.workspace, "dynamic.mjs");
    const dynamicPythonScript = join(f.workspace, "dynamic.py");
    writeFileSync(target, "old\n");
    writeFileSync(owned, "old\n");
    writeFileSync(shellScript, `printf changed > ${target}\n`);
    writeFileSync(nodeScript, `import { writeFileSync } from "node:fs";\nwriteFileSync("${target}", "changed");\n`);
    writeFileSync(pythonScript, `from pathlib import Path\nPath("${target}").write_text("changed")\n`);
    writeFileSync(helper, "#!/bin/sh\nprintf safe\n");
    writeFileSync(executeScript, `import { execFileSync } from "node:child_process";\nexecFileSync("${helper}", []);\n`);
    writeFileSync(pythonHelper, "value = 1\n");
    writeFileSync(pythonImportScript, "import local_helper\nprint(local_helper.value)\n");
    writeFileSync(nodeHelper, "export const value = 1;\n");
    writeFileSync(nodeImportScript, 'import { value } from "./local-helper.mjs";\nconsole.log(value);\n');
    writeFileSync(dynamicShellScript, 'rm "$RUNTIME"\n');
    writeFileSync(dynamicNodeScript, 'import { writeFileSync } from "node:fs";\nwriteFileSync(runtimePath, "changed");\n');
    writeFileSync(dynamicPythonScript, 'open(runtime_path, "w")\n');
    f.policy.addCreated(owned);
    f.policy.save("local", {
      version: 3,
      ownership: {
        edit: [],
        execute: [],
        full: [
          "mutate.sh", "mutate.mjs", "mutate.py", "execute.mjs", "imports.py", "imports.mjs",
          "dynamic.sh", "dynamic.mjs", "dynamic.py",
        ],
      },
      secrets: [],
      commands: { include: [], exclude: [] },
    });

    for (const command of [`bash ${shellScript}`, `node ${nodeScript}`, `python ${pythonScript}`]) {
      const result = f.analyzer.analyzeCommand(command, f.workspace);
      assert.equal(result.decision, "ask", command);
      assert.deepEqual(result.ownershipCandidates, [{ path: target, required: "edit" }]);
    }
    const sourced = f.analyzer.analyzeCommand(`source ${shellScript}`, f.workspace);
    assert.equal(sourced.decision, "ask");
    assert.deepEqual(sourced.ownershipCandidates, [{ path: target, required: "edit" }]);
    const execution = f.analyzer.analyzeCommand(`node ${executeScript}`, f.workspace);
    assert.equal(execution.decision, "ask");
    assert.deepEqual(execution.ownershipCandidates, [{ path: helper, required: "execute" }]);
    const imported = f.analyzer.analyzeCommand(`python ${pythonImportScript}`, f.workspace);
    assert.equal(imported.decision, "ask");
    assert.deepEqual(imported.ownershipCandidates, [{ path: pythonHelper, required: "execute" }]);
    const nodeImported = f.analyzer.analyzeCommand(`node ${nodeImportScript}`, f.workspace);
    assert.equal(nodeImported.decision, "ask");
    assert.deepEqual(nodeImported.ownershipCandidates, [{ path: nodeHelper, required: "execute" }]);
    for (const command of [
      `bash ${dynamicShellScript}`,
      `node ${dynamicNodeScript}`,
      `python ${dynamicPythonScript}`,
    ]) {
      assert.equal(f.analyzer.analyzeCommand(command, f.workspace).decision, "allow", command);
    }
    assert.equal(
      f.analyzer.analyzeCommand(`node -e 'require("node:fs").writeFileSync("${owned}", "changed")'`, f.workspace).decision,
      "allow",
    );
    const newNodePath = join(f.workspace, "node-created.txt");
    const nodeCreation = f.analyzer.analyzeCommand(`node -e 'require("node:fs").writeFileSync("${newNodePath}", "created")'`, f.workspace);
    assert.equal(nodeCreation.decision, "allow");
    assert.deepEqual(nodeCreation.creationCandidates, [newNodePath]);
    assert.equal(
      f.analyzer.analyzeCommand(`python -c 'open("${owned}", "w").write("changed")'`, f.workspace).decision,
      "allow",
    );
    const gitMetadata = join(f.workspace, ".git", "config");
    mkdirSync(join(f.workspace, ".git"));
    writeFileSync(gitMetadata, "old\n");
    assert.equal(
      f.analyzer.analyzeCommand(`node -e 'require("node:fs").writeFileSync("${gitMetadata}", "changed")'`, f.workspace).decision,
      "deny",
    );
    for (const command of [
      `node -e 'require("node:fs").writeFileSync(runtimePath, "changed")'`,
      `node -e 'require("node:child_process").execSync(runtimeCommand)'`,
      `node -e 'require("node:child_process").spawnSync("printf", [runtimeValue])'`,
      `node -e 'require("node:child_process").spawnSync("rm", [runtimeValue])'`,
      `python -c 'import subprocess; subprocess.run(["printf", runtime_value])'`,
      `node -e 'import(runtimeModule)'`,
      `python -c 'import importlib; importlib.import_module(runtime_module)'`,
      `python -c 'import subprocess; subprocess.run(["rm", runtime_value], cwd=runtime_cwd)'`,
      `python -c 'open(runtime_path, "w")'`,
      `bash -c 'rm "$RUNTIME"'`,
      `bash -c 'printf value > "$RUNTIME"'`,
      `bash -c 'chmod 600 "$RUNTIME"'`,
      `bash -c 'npm run "$SCRIPT"'`,
      `bash -c 'npm --workspace "$WORKSPACE" test'`,
      `bash -c 'npm --script-shell "$SHELL" test'`,
      `bash -c 'cp "$SOURCE" "$DESTINATION"'`,
      `bash -c 'mv "$SOURCE" "$DESTINATION"'`,
      `bash -c '"$COMMAND" --flag'`,
      `bash -c 'source "$MODULE"'`,
      `bash -c 'git -C "$ROOT" init'`,
      `bash -c 'curl -X POST "$URL"'`,
      `bash -c 'cat "$ROOT/path"'`,
      `python -c 'print("$ROOT/path")'`,
      `bash -c 'sudo rm "$TARGET"'`,
    ]) {
      const result = f.analyzer.analyzeCommand(command, f.workspace);
      assert.equal(result.decision, "allow", command);
      assert.equal(result.reasons.some((reason) => /[Dd]ynamic|unresolved/.test(reason)), false, command);
    }
    assert.match(f.analyzer.analyzeCommand(`rm "$RUNTIME"`, f.workspace).reasons.join(" "), /Dynamic deletion target/);
    assert.match(f.analyzer.analyzeCommand(`printf value > "$RUNTIME"`, f.workspace).reasons.join(" "), /Dynamic redirection target/);
    assert.match(f.analyzer.analyzeCommand(`chmod 600 "$RUNTIME"`, f.workspace).reasons.join(" "), /dynamic mutation arguments/);
    assert.match(f.analyzer.analyzeCommand(`npm run "$SCRIPT"`, f.workspace).reasons.join(" "), /script name cannot be resolved/);
    assert.match(f.analyzer.analyzeCommand(`npm --workspace "$WORKSPACE" test`, f.workspace).reasons.join(" "), /workspace/);
    assert.match(f.analyzer.analyzeCommand(`npm --script-shell "$SHELL" test`, f.workspace).reasons.join(" "), /script shell/);
    assert.match(f.analyzer.analyzeCommand(`cp "$SOURCE" "$DESTINATION"`, f.workspace).reasons.join(" "), /Dynamic cp path/);
    assert.match(f.analyzer.analyzeCommand(`mv "$SOURCE" "$DESTINATION"`, f.workspace).reasons.join(" "), /Dynamic mv path/);
    assert.match(f.analyzer.analyzeCommand(`"$COMMAND" --flag`, f.workspace).reasons.join(" "), /Executable variable/);
    assert.match(f.analyzer.analyzeCommand(`source "$MODULE"`, f.workspace).reasons.join(" "), /Dynamic execution target/);
    assert.match(f.analyzer.analyzeCommand(`git -C "$ROOT" init`, f.workspace).reasons.join(" "), /Mutative or unknown Git/);
    assert.match(f.analyzer.analyzeCommand(`curl -X POST "$URL"`, f.workspace).reasons.join(" "), /may mutate remote/);
    assert.match(f.analyzer.analyzeCommand(`sudo rm "$TARGET"`, f.workspace).reasons.join(" "), /Elevated execution/);
    assert.match(
      f.analyzer.analyzeCommand(`bash -c 'mystery-command --flag'`, f.workspace).reasons.join(" "),
      /Unknown command mystery-command/,
    );
    assert.equal(
      f.analyzer.analyzeCommand(`bash -c 'curl -X POST https://example.invalid/resource'`, f.workspace).decision,
      "ask",
    );
    assert.match(
      f.analyzer.analyzeCommand(`node -e 'require("node:child_process").spawnSync("mystery-command")'`, f.workspace).reasons.join(" "),
      /Unknown command mystery-command/,
    );
    const partiallyConcreteCopy = f.analyzer.analyzeCommand(
      `bash -c 'cp "$SOURCE" "${target}"'`,
      f.workspace,
    );
    assert.equal(partiallyConcreteCopy.decision, "ask");
    assert.deepEqual(partiallyConcreteCopy.ownershipCandidates, [{ path: target, required: "edit" }]);
    const partiallyConcreteDelete = f.analyzer.analyzeCommand(
      `node -e 'require("node:child_process").spawnSync("rm", ["${target}", runtimeValue])'`,
      f.workspace,
    );
    assert.equal(partiallyConcreteDelete.decision, "deny");
    assert.match(partiallyConcreteDelete.reasons.join(" "), /deletion without edit ownership is prohibited/i);
    const partiallyConcreteCatastrophe = f.analyzer.analyzeCommand(
      `node -e 'require("node:child_process").spawnSync("shutdown", [runtimeValue])'`,
      f.workspace,
    );
    assert.equal(partiallyConcreteCatastrophe.decision, "deny");
    assert.match(partiallyConcreteCatastrophe.reasons.join(" "), /system power operation/);
    const dynamicFindCatastrophe = f.analyzer.analyzeCommand(
      `bash -c 'find "$ROOT" -exec shutdown now \\;'`,
      f.workspace,
    );
    assert.equal(dynamicFindCatastrophe.decision, "deny");
    assert.match(dynamicFindCatastrophe.reasons.join(" "), /system power operation/);
    const dynamicCwdCatastrophe = f.analyzer.analyzeCommand(
      `python -c 'import subprocess; subprocess.run(["shutdown", runtime_value], cwd=runtime_cwd)'`,
      f.workspace,
    );
    assert.equal(dynamicCwdCatastrophe.decision, "deny");
    assert.match(dynamicCwdCatastrophe.reasons.join(" "), /system power operation/);
    const partiallyConcreteExecution = f.analyzer.analyzeCommand(
      `node -e 'require("node:child_process").spawnSync("${helper}", [runtimeValue])'`,
      f.workspace,
    );
    assert.equal(partiallyConcreteExecution.decision, "ask");
    assert.deepEqual(partiallyConcreteExecution.ownershipCandidates, [{ path: helper, required: "execute" }]);
  } finally { f.cleanup(); }
});

test("Julia inline and file source use static evidence without outer path misclassification", () => {
  const f = fixture();
  try {
    const target = join(f.workspace, "julia-target.txt");
    const secret = join(f.workspace, ".env");
    const gitDirectory = join(f.workspace, ".git");
    const gitConfig = join(gitDirectory, "config");
    const helper = join(f.workspace, "julia-helper.sh");
    const mainScript = join(f.workspace, "main.jl");
    const includedScript = join(f.workspace, "included.jl");
    const dynamicScript = join(f.workspace, "dynamic.jl");
    const baseline = join(f.workspace, "baseline.sha256");
    writeFileSync(target, "old\n");
    writeFileSync(secret, "TOKEN=test\n");
    mkdirSync(gitDirectory);
    writeFileSync(gitConfig, "old\n");
    writeFileSync(helper, "#!/bin/sh\nprintf safe\n");
    writeFileSync(baseline, "hash path\n");
    writeFileSync(mainScript, 'include("included.jl")\n');
    writeFileSync(includedScript, `write("${target}", "changed")\n`);
    writeFileSync(dynamicScript, 'write(runtime_path, "changed")\n');
    f.policy.save("local", {
      version: 3,
      ownership: { edit: [], execute: [], full: ["main.jl", "included.jl", "dynamic.jl"] },
      secrets: [],
      commands: { include: [], exclude: [] },
    });

    const nodeDiagnostic = f.analyzer.analyzeCommand(
      `node --input-type=module -e 'import { value } from "./missing-local.mjs"; const source="scripts/output/value"; const command=\`julia -e \${JSON.stringify(source)}\`; console.log(command, value);'`,
      f.workspace,
    );
    assert.equal(nodeDiagnostic.decision, "allow");
    assert.equal(nodeDiagnostic.reasons.some((reason) => /Dynamic path/.test(reason)), false);
    assert.deepEqual(nodeDiagnostic.pathExpansions ?? [], []);

    const verificationSource = [
      "using SHA,TOML",
      `rec=TOML.parsefile("${join(f.workspace, "verification.toml")}")`,
      'old=read(`git show HEAD:main.tex`,String)',
      `new=read("${join(f.workspace, "main.tex")}",String)`,
      `for line in eachline("${baseline}"); hash,path=split(line;limit=2); open(sha256,path); end`,
    ].join("; ");
    const verification = f.analyzer.analyzeCommand(
      `julia --startup-file=no --project=scripts/threshold_flux -e '${verificationSource}'`,
      f.workspace,
    );
    assert.equal(verification.decision, "allow");
    assert.equal(verification.reasons.some((reason) => /Dynamic path|Opaque julia|Unknown command julia/.test(reason)), false);
    assert.deepEqual(verification.pathExpansions ?? [], []);
    assert.equal(f.analyzer.analyzeCommand(`julia --eval='println("scripts/$runtime/value")'`, f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand(`julia -E'println("safe")'`, f.workspace).decision, "allow");
    const elevatedInline = f.analyzer.analyzeCommand(`sudo julia -e 'println("scripts/$runtime/value")'`, f.workspace);
    assert.equal(elevatedInline.decision, "ask");
    assert.match(elevatedInline.reasons.join(" "), /Elevated execution/);
    assert.doesNotMatch(elevatedInline.reasons.join(" "), /Dynamic path/);

    const concreteMutation = f.analyzer.analyzeCommand(`julia -e 'write("${target}", "changed")'`, f.workspace);
    assert.equal(concreteMutation.decision, "ask");
    assert.deepEqual(concreteMutation.ownershipCandidates, [{ path: target, required: "edit" }]);
    assert.equal(f.analyzer.analyzeCommand(`julia -e 'rm("${target}")'`, f.workspace).decision, "deny");
    const partiallyConcreteDelete = f.analyzer.analyzeCommand(`julia -e 'run(Cmd(["rm", "${target}", runtime_argument]))'`, f.workspace);
    assert.equal(partiallyConcreteDelete.decision, "deny");
    assert.match(partiallyConcreteDelete.reasons.join(" "), /deletion without edit ownership/i);
    assert.equal(f.analyzer.analyzeCommand(`julia -e 'write(runtime_path, "changed")'`, f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand(`julia -e 'run(runtime_command)'`, f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand(`julia -e 'read("${secret}", String)'`, f.workspace).decision, "deny");
    assert.equal(f.analyzer.analyzeCommand(`julia -e 'write("${gitConfig}", "changed")'`, f.workspace).decision, "deny");

    const catastrophic = f.analyzer.analyzeCommand("julia -e 'run(`shutdown now`)'", f.workspace);
    assert.equal(catastrophic.decision, "deny");
    assert.match(catastrophic.reasons.join(" "), /system power operation/);
    const dynamicCwdCatastrophic = f.analyzer.analyzeCommand(`julia -e 'run(Cmd(["shutdown", runtime_argument]; dir=runtime_directory))'`, f.workspace);
    assert.equal(dynamicCwdCatastrophic.decision, "deny");
    assert.match(dynamicCwdCatastrophic.reasons.join(" "), /system power operation/);
    const concreteExecution = f.analyzer.analyzeCommand(`julia -e 'run(\`${helper}\`)'`, f.workspace);
    assert.equal(concreteExecution.decision, "ask");
    assert.deepEqual(concreteExecution.ownershipCandidates, [{ path: helper, required: "execute" }]);

    const includedMutation = f.analyzer.analyzeCommand(`julia ${mainScript}`, f.workspace);
    assert.equal(includedMutation.decision, "ask");
    assert.deepEqual(includedMutation.ownershipCandidates, [{ path: target, required: "edit" }]);
    assert.equal(f.analyzer.analyzeCommand(`julia ${dynamicScript}`, f.workspace).decision, "allow");
    const preloadMutation = f.analyzer.analyzeCommand(`julia -L ${includedScript} -e 'println("safe")'`, f.workspace);
    assert.equal(preloadMutation.decision, "ask");
    assert.deepEqual(preloadMutation.ownershipCandidates, [{ path: target, required: "edit" }]);

    const externalPreload = join(f.root, "external-preload.jl");
    writeFileSync(externalPreload, `write("${target}", "external mutation")\n`);
    f.policy.save("local", {
      version: 3,
      ownership: { edit: [], execute: [], full: ["main.jl", "included.jl", "dynamic.jl", externalPreload] },
      secrets: [],
      commands: { include: [], exclude: [] },
    });
    const externalPreloadRun = f.analyzer.analyzeCommand(`julia -L ${externalPreload} -e 'println("safe")'`, f.workspace);
    assert.equal(externalPreloadRun.decision, "ask");
    assert.deepEqual(externalPreloadRun.ownershipCandidates, [{ path: target, required: "edit" }]);

    const depotDirectory = join(f.workspace, ".julia", "packages", "Fixture", "hash");
    const depotSource = join(depotDirectory, "Fixture.jl");
    mkdirSync(depotDirectory, { recursive: true });
    writeFileSync(depotSource, `write("${target}", "dependency mutation")\n`);
    f.policy.save("local", {
      version: 3,
      ownership: { edit: [], execute: [], full: ["main.jl", "included.jl", "dynamic.jl", ".julia/packages/**"] },
      secrets: [],
      commands: { include: [], exclude: [] },
    });
    const depotRun = f.analyzer.analyzeCommand(`julia -L ${depotSource} -e 'println("safe")'`, f.workspace);
    assert.equal(depotRun.decision, "allow");
    assert.doesNotMatch(depotRun.reasons.join(" "), /julia-target|dependency mutation/);

    const invalid = f.analyzer.analyzeCommand("julia -e 'function broken('", f.workspace);
    assert.equal(invalid.decision, "ask");
    assert.match(invalid.reasons.join(" "), /Julia syntax could not be parsed completely/);

    const directDynamic = f.analyzer.analyzeCommand('cat "$RUNTIME/path"', f.workspace);
    assert.equal(directDynamic.decision, "ask");
    assert.match(directDynamic.reasons.join(" "), /Dynamic path cannot be resolved statically/);
  } finally { f.cleanup(); }
});
test("source screening uses static evidence and stops at external dependency boundaries", () => {
  const f = fixture();
  try {
    const testsDirectory = join(f.workspace, "tests");
    const testFile = join(testsDirectory, "dynamic-fixture.test.ts");
    const packageJson = join(f.workspace, "package.json");
    mkdirSync(testsDirectory);
    writeFileSync(packageJson, JSON.stringify({ scripts: {
      pretest: 'rm "$DYNAMIC_PRETEST_TARGET"',
      test: "node --test tests/*.test.ts",
    } }));
    writeFileSync(testFile, [
      'import test from "node:test";',
      'import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";',
      'import { spawnSync } from "node:child_process";',
      'import { tmpdir } from "node:os";',
      'import { join } from "node:path";',
      'function fixture() {',
      '  const root = mkdtempSync(join(tmpdir(), "bash-guard-static-evidence-"));',
      '  return { root, path: join(root, "value.txt") };',
      '}',
      'function run(command, args) { return spawnSync(command, args); }',
      'test("isolated fixture", () => {',
      '  const value = fixture();',
      '  mkdirSync(join(value.root, "nested"));',
      '  writeFileSync(value.path, "value");',
      '  readFileSync(value.path, "utf8");',
      '  run("git", ["-C", value.root, "init", "--quiet"]);',
      '  rmSync(value.root, { recursive: true, force: true });',
      '});',
    ].join("\n"));
    f.policy.save("local", {
      version: 3,
      ownership: { edit: [], execute: [], full: ["tests/**"] },
      secrets: [],
      commands: { include: [], exclude: [] },
    });
    const npmTest = f.analyzer.analyzeCommand("npm test", f.workspace);
    assert.equal(npmTest.decision, "allow");
    assert.equal(npmTest.reasons.some((reason) => /dynamic|unresolved/i.test(reason)), false);

    const application = join(f.workspace, "packages", "app");
    const localEntry = join(application, "entry.mjs");
    const localHelper = join(f.workspace, "shared-helper.mjs");
    const concreteTarget = join(f.workspace, "concrete-unowned.txt");
    mkdirSync(application, { recursive: true });
    writeFileSync(concreteTarget, "old\n");
    writeFileSync(localHelper, `import { writeFileSync } from "node:fs";\nwriteFileSync("${concreteTarget}", "changed");\n`);
    writeFileSync(localEntry, 'import "../../shared-helper.mjs";\n');
    f.policy.save("local", {
      version: 3,
      ownership: { edit: [], execute: [], full: ["packages/**", "shared-helper.mjs"] },
      secrets: [],
      commands: { include: [], exclude: [] },
    });
    const localImport = f.analyzer.analyzeCommandUnits(`cd ${application} && node entry.mjs`, f.workspace).at(-1)!.analysis;
    assert.equal(localImport.decision, "ask");
    assert.deepEqual(localImport.ownershipCandidates, [{ path: concreteTarget, required: "edit" }]);

    const oversizedLocal = join(f.workspace, "oversized-local.mjs");
    const oversizedEntry = join(f.workspace, "oversized-entry.mjs");
    writeFileSync(oversizedLocal, `// bounded local source\n${" ".repeat(262_145)}`);
    writeFileSync(oversizedEntry, 'import "./oversized-local.mjs";\n');
    f.policy.save("local", {
      version: 3,
      ownership: { edit: [], execute: [], full: ["oversized-entry.mjs", "oversized-local.mjs"] },
      secrets: [],
      commands: { include: [], exclude: [] },
    });
    const oversizedRun = f.analyzer.analyzeCommand(`node ${oversizedEntry}`, f.workspace);
    assert.equal(oversizedRun.decision, "ask");
    assert.match(oversizedRun.reasons.join(" "), /256 KiB/);

    const compiler = join(f.systemReadonly, "typescript", "bin", "tsc.js");
    mkdirSync(join(f.systemReadonly, "typescript", "bin"), { recursive: true });
    writeFileSync(compiler, `// immutable compiler implementation\n${" ".repeat(262_145)}`);
    const compilerCheck = f.analyzer.analyzeCommand(`node ${compiler} --project ${f.workspace}`, f.workspace);
    assert.equal(compilerCheck.decision, "allow");
    assert.doesNotMatch(compilerCheck.reasons.join(" "), /256 KiB/);

    const dependencyDirectory = join(f.workspace, "node_modules", "fixture-package");
    const dependency = join(dependencyDirectory, "index.js");
    const entry = join(f.workspace, "dependency-entry.mjs");
    mkdirSync(dependencyDirectory, { recursive: true });
    writeFileSync(dependency, `// installed dependency\n${" ".repeat(262_145)}`);
    writeFileSync(entry, 'import "./node_modules/fixture-package/index.js";\n');
    f.policy.save("local", {
      version: 3,
      ownership: { edit: [], execute: [], full: ["dependency-entry.mjs", "node_modules/**"] },
      secrets: [],
      commands: { include: [], exclude: [] },
    });
    const dependencyRun = f.analyzer.analyzeCommand(`node ${entry}`, f.workspace);
    assert.equal(dependencyRun.decision, "allow");
    assert.doesNotMatch(dependencyRun.reasons.join(" "), /256 KiB/);

    const outside = join(f.root, "outside-module.mjs");
    const escaped = join(f.workspace, "escaped-module.mjs");
    const escapedEntry = join(f.workspace, "escaped-entry.mjs");
    writeFileSync(outside, `// source outside project\n${" ".repeat(262_145)}`);
    symlinkSync(outside, escaped);
    writeFileSync(escapedEntry, 'import "./escaped-module.mjs";\n');
    f.policy.save("local", {
      version: 3,
      ownership: { edit: [], execute: [], full: ["escaped-entry.mjs", outside] },
      secrets: [],
      commands: { include: [], exclude: [] },
    });
    const escapedRun = f.analyzer.analyzeCommand(`node ${escapedEntry}`, f.workspace);
    assert.equal(escapedRun.decision, "allow");
    assert.doesNotMatch(escapedRun.reasons.join(" "), /256 KiB/);

    const externalEntry = join(f.root, "external-entry.mjs");
    writeFileSync(externalEntry, `import { writeFileSync } from "node:fs";\nwriteFileSync("${concreteTarget}", "changed");\n`);
    f.policy.save("local", {
      version: 3,
      ownership: { edit: [], execute: [], full: [externalEntry] },
      secrets: [],
      commands: { include: [], exclude: [] },
    });
    const externalRun = f.analyzer.analyzeCommand(`node ${externalEntry}`, f.workspace);
    assert.equal(externalRun.decision, "ask");
    assert.deepEqual(externalRun.ownershipCandidates, [{ path: concreteTarget, required: "edit" }]);
  } finally { f.cleanup(); }
});


test("inline heredocs are language-screened and retain shell command order", () => {
  const f = fixture();
  try {
    const target = join(f.workspace, "heredoc-target.txt");
    writeFileSync(target, "old\n");
    const safe = f.analyzer.analyzeCommandUnits([
      `cd ${f.workspace} && node --input-type=module - <<'NODE'`,
      'import { parse } from "@babel/parser";',
      'const fixture = "git push --force origin main";',
      'console.log(parse("const x = 1").type, fixture);',
      "NODE",
      "printf done",
    ].join("\n"), f.root);
    assert.deepEqual(safe.map((unit) => unit.analysis.decision), ["allow", "allow", "allow"]);
    assert.equal(safe.some((unit) => /^import\s/.test(unit.command)), false);
    const inertShellData = f.analyzer.analyzeCommandUnits("cat <<'DATA'\nrm /\nDATA\n", f.workspace);
    assert.equal(inertShellData.length, 1);
    assert.equal(inertShellData[0]!.analysis.decision, "allow");
    const expandedShellData = f.analyzer.analyzeCommandUnits(["cat <<DATA", "$(shutdown now)", "DATA"].join("\n"), f.workspace);
    assert.equal(expandedShellData[0]!.analysis.decision, "deny");

    const mutative = f.analyzer.analyzeCommandUnits([
      "python - <<'PY'",
      "from pathlib import Path",
      `Path("${target}").write_text("changed")`,
      "PY",
    ].join("\n"), f.workspace);
    assert.equal(mutative.length, 1);
    assert.equal(mutative[0]!.analysis.decision, "ask");
    assert.deepEqual(mutative[0]!.analysis.ownershipCandidates, [{ path: target, required: "edit" }]);
    const juliaMutative = f.analyzer.analyzeCommandUnits([
      "julia --startup-file=no - <<'JULIA'",
      `write("${target}", "changed")`,
      "JULIA",
    ].join("\n"), f.workspace);
    assert.equal(juliaMutative.length, 1);
    assert.equal(juliaMutative[0]!.analysis.decision, "ask");
    assert.deepEqual(juliaMutative[0]!.analysis.ownershipCandidates, [{ path: target, required: "edit" }]);
  } finally { f.cleanup(); }
});

test("informational runtime and package-manager commands are allowed narrowly", () => {
  const f = fixture();
  try {
    const script = join(f.workspace, "check.js");
    writeFileSync(script, "const value = 1;\n");
    const fakeNode = join(f.workspace, "node");
    writeFileSync(fakeNode, "#!/bin/sh\nprintf fake\n");
    for (const command of [
      "npm view @lezer/python version --json",
      "npm ls @lezer/python --depth=0",
      "npm audit --omit=dev",
      "node --version",
      "python --version",
      "julia --version",
      "python -m pip list",
      `node --check ${script}`,
    ]) assert.equal(f.analyzer.analyzeCommand(command, f.workspace).decision, "allow", command);
    assert.equal(f.analyzer.analyzeCommand(`${fakeNode} --version`, f.workspace).decision, "ask");

    for (const command of ["npm audit fix", "npm version patch", "python -m pip install package", "python -v"]) {
      assert.equal(f.analyzer.analyzeCommand(command, f.workspace).decision, "ask", command);
    }
  } finally { f.cleanup(); }
});


test("npm test analyzes local lifecycle scripts and nested Node tests", () => {
  const f = fixture();
  try {
    const safeTest = join(f.workspace, "npm-safe.test.ts");
    const otherTest = join(f.workspace, "npm-other.test.ts");
    const packageJson = join(f.workspace, "package.json");
    writeFileSync(safeTest, 'const fixture = "git push --force origin main";\n');
    writeFileSync(otherTest, 'const fixture = "shutdown now";\n');
    writeFileSync(packageJson, JSON.stringify({ scripts: {
      pretest: "printf pre",
      test: "node --test *.test.ts",
      posttest: "printf post",
    } }));
    f.policy.save("local", {
      version: 3,
      ownership: { edit: [], execute: [], full: ["*.test.ts"] },
      secrets: [],
      commands: { include: [], exclude: [] },
    });

    const safe = f.analyzer.analyzeCommand("npm test", f.workspace);
    assert.equal(safe.decision, "allow");
    assert.deepEqual(safe.accesses.map((access) => access.path), [packageJson, otherTest, safeTest]);
    assert.equal(f.analyzer.analyzeCommand(`npm test -- 'git push --force origin main'`, f.workspace).decision, "allow");

    writeFileSync(packageJson, JSON.stringify({ scripts: { test: "git push --force origin main" } }));
    const dangerous = f.analyzer.analyzeCommand("npm run test", f.workspace);
    assert.equal(dangerous.decision, "deny");
    assert.match(dangerous.reasons.join(" "), /Destructive Git operation/);

    writeFileSync(packageJson, JSON.stringify({ scripts: { test: "npm test" } }));
    const recursive = f.analyzer.analyzeCommand("npm test", f.workspace);
    assert.equal(recursive.decision, "ask");
    assert.match(recursive.reasons.join(" "), /Recursive npm script/);
  } finally { f.cleanup(); }
});

test("explicit secret references in a full-owned script are denied", () => {
  const f = fixture();
  try {
    const secret = join(f.workspace, ".env");
    const script = join(f.workspace, "secret-reader.sh");
    const nodeScript = join(f.workspace, "secret-reader.mjs");
    const pythonScript = join(f.workspace, "secret_reader.py");
    const juliaScript = join(f.workspace, "secret_reader.jl");
    writeFileSync(secret, "TOKEN=test\n");
    writeFileSync(script, `#!/bin/sh\ncat ${secret}\n`);
    writeFileSync(nodeScript, `import { readFileSync } from "node:fs";\nreadFileSync("${secret}", "utf8");\n`);
    writeFileSync(pythonScript, `open("${secret}").read()\n`);
    writeFileSync(juliaScript, `read("${secret}", String)\n`);
    f.policy.save("local", { version: 3, ownership: { edit: [], execute: [], full: ["secret-reader.sh", "secret-reader.mjs", "secret_reader.py", "secret_reader.jl"] }, secrets: [], commands: { include: [], exclude: [] } });
    assert.equal(f.analyzer.analyzeCommand(`bash ${script}`, f.workspace).decision, "deny");
    assert.equal(f.analyzer.analyzeCommand(`node ${nodeScript}`, f.workspace).decision, "deny");
    assert.equal(f.analyzer.analyzeCommand(`python ${pythonScript}`, f.workspace).decision, "deny");
    assert.equal(f.analyzer.analyzeCommand(`julia ${juliaScript}`, f.workspace).decision, "deny");
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
    assert.equal(f.analyzer.analyzeCommand("find . -exec rm / \\;", f.workspace).decision, "deny");
    assert.equal(f.analyzer.analyzeCommand("xargs -n 1 git push --force origin main", f.workspace).decision, "deny");
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

test("Nix store queries and Hyprland inspection commands are read-only", () => {
  const f = fixture();
  try {
    const storePath = join(f.systemReadonly, "example-package");
    const derivation = `${storePath}.drv`;
    writeFileSync(storePath, "output\n");
    writeFileSync(derivation, "derivation\n");
    for (const command of [
      `nix-store -q --deriver ${storePath}`,
      `nix-store --query --references ${storePath}`,
      `nix derivation show ${derivation}`,
      `nix path-info --json ${storePath}`,
      "nix --version",
      "nix-store --help",
      "hyprctl binds",
      "hyprctl -j clients",
      "hyprctl instances -j",
      "hyprctl configerrors",
      "hyprctl --help",
    ]) assert.equal(f.analyzer.analyzeCommand(command, f.workspace).decision, "allow", command);
    const assignedQuery = f.analyzer.analyzeCommandUnits(`store=${storePath}; nix-store -q --deriver "$store"`, f.workspace);
    assert.equal(assignedQuery.every((unit) => unit.analysis.decision === "allow"), true);
    assert.deepEqual(assignedQuery.at(-1)?.resolvedBindings, [{ name: "store", value: storePath }]);
    assert.equal(f.analyzer.analyzeCommand(`nix-store -q --force-realise ${storePath}`, f.workspace).decision, "ask");
    assert.equal(f.analyzer.analyzeCommand(`nix build ${storePath}`, f.workspace).decision, "ask");
    assert.equal(f.analyzer.analyzeCommand("nix run .#tool -- --help", f.workspace).decision, "ask");
    assert.equal(f.analyzer.analyzeCommand("hyprctl dispatch closewindow active", f.workspace).decision, "ask");
    assert.equal(f.analyzer.analyzeCommand("hyprctl dispatch exec --help", f.workspace).decision, "ask");
    assert.equal(f.analyzer.analyzeCommand("hyprctl --batch 'dispatch workspace 1'", f.workspace).decision, "ask");
  } finally { f.cleanup(); }
});

test("command substitutions execute without turning assignment suffixes into commands", () => {
  const f = fixture();
  try {
    const command = "log=${XDG_RUNTIME_DIR:-/run/user/$UID}/hypr/$(hyprctl instances -j | jq -r '.instance')/hyprland.log";
    const result = f.analyzer.analyzeCommand(command, f.workspace);
    assert.equal(result.decision, "allow");
    assert.deepEqual(result.ownershipCandidates, []);
    assert.equal(result.accesses.some((access) => access.path.endsWith("/hyprland.log")), false);

    const nested = f.analyzer.analyzeCommand("value=$(unknown-inspector --flag)/suffix.txt", f.workspace);
    assert.equal(nested.decision, "ask");
    assert.deepEqual(nested.reasons, ["Unknown command unknown-inspector requires approval"]);
    assert.deepEqual(nested.ownershipCandidates, []);
    assert.equal(f.analyzer.analyzeCommand("printf '%s' '$(unknown-inspector)'", f.workspace).decision, "allow");
    assert.match(f.analyzer.analyzeCommand("value=`unknown-inspector --flag`", f.workspace).reasons.join(" "), /Unknown command unknown-inspector/);
  } finally { f.cleanup(); }
});

test("known-missing literal paths do not require ownership", () => {
  const f = fixture();
  try {
    const missing = join(f.workspace, "does-not-exist.sh");
    const result = f.analyzer.analyzeCommand(missing, f.workspace);
    assert.equal(result.decision, "allow");
    assert.deepEqual(result.ownershipCandidates, []);
    assert.equal(result.accesses[0]?.existed, false);
    assert.equal(f.analyzer.analyzeCommand(`cat ${join(f.workspace, ".env")}`, f.workspace).decision, "deny");
  } finally { f.cleanup(); }
});

test("shell globs and loop path variables expand to concrete prompt paths", () => {
  const f = fixture();
  try {
    const luaRoot = join(f.workspace, ".config", "hypr", "lua");
    mkdirSync(luaRoot, { recursive: true });
    const main = join(f.workspace, ".config", "hypr", "hyprland.lua");
    const first = join(luaRoot, "first.lua");
    const second = join(luaRoot, "second.lua");
    writeFileSync(main, "return {}\n");
    writeFileSync(first, "return {}\n");
    writeFileSync(second, "return {}\n");
    const pattern = join(luaRoot, "*.lua");

    const unknown = f.analyzer.analyzeCommand(`unknown-inspector ${pattern}`, f.workspace);
    assert.equal(unknown.decision, "ask");
    assert.deepEqual(unknown.accesses.map(({ path }) => path), [first, second]);
    assert.deepEqual(unknown.ownershipCandidates, [
      { path: first, required: "edit" },
      { path: second, required: "edit" },
    ]);
    assert.deepEqual(unknown.pathExpansions, [{ expression: pattern, matches: [first, second] }]);
    assert.equal(unknown.reasons.some((reason) => reason.includes("*.lua")), false);
    const unmatched = f.analyzer.analyzeCommand(`unknown-inspector ${join(luaRoot, "missing-*.lua")}`, f.workspace);
    assert.deepEqual(unmatched.ownershipCandidates, []);
    assert.deepEqual(unmatched.pathExpansions, [{ expression: join(luaRoot, "missing-*.lua"), matches: [] }]);
    const secret = join(f.workspace, ".env");
    writeFileSync(secret, "TOKEN=test\n");
    assert.equal(f.analyzer.analyzeCommand(`cat ${join(f.workspace, ".*")}`, f.workspace).decision, "deny");

    const assigned = f.analyzer.analyzeCommandUnits(`dir=${luaRoot}; unknown-inspector "$dir"/*.lua`, f.workspace).at(-1)!;
    assert.deepEqual(assigned.analysis.accesses.map(({ path }) => path), [first, second]);
    assert.deepEqual(assigned.resolvedBindings, [{ name: "dir", value: luaRoot }]);

    const loop = "then for file in .config/hypr/hyprland.lua .config/hypr/lua/*.lua; do lua -e 'assert(loadfile(arg[1]))' \"$file\"; done";
    const requiring = f.analyzer.analyzeCommandUnits(loop, f.workspace).filter((unit) => unit.analysis.decision !== "allow");
    assert.deepEqual(requiring.map((unit) => unit.resolvedBindings), [
      [{ name: "file", value: main }],
      [{ name: "file", value: first }],
      [{ name: "file", value: second }],
    ]);
    assert.equal(requiring.every((unit) => unit.analysis.reasons.join(" ") === "Opaque lua inline code requires approval"), true);
    assert.equal(requiring.every((unit) => unit.analysis.accesses.length === 0), true);

    const unresolved = f.analyzer.analyzeCommand("unknown-inspector $runtime/*.lua", f.workspace);
    assert.match(unresolved.reasons.join(" "), /Dynamic path cannot be resolved statically/);
    assert.deepEqual(unresolved.ownershipCandidates, []);
    assert.deepEqual(unresolved.pathExpansions, [{ expression: "$runtime/*.lua", matches: [], unresolved: true }]);
  } finally { f.cleanup(); }
});

test("quoted Lua source is opaque code rather than a path or unknown command", () => {
  const f = fixture();
  try {
    const result = f.analyzer.analyzeCommand("do lua -e 'assert(loadfile(arg[1]))' \"$file\"", f.workspace);
    assert.equal(result.decision, "ask");
    assert.deepEqual(result.reasons, ["Opaque lua inline code requires approval"]);
    assert.deepEqual(result.accesses, []);
    assert.deepEqual(result.ownershipCandidates, []);
    const sourceWithDynamicSyntax = f.analyzer.analyzeCommand(`lua -e 'print("$ROOT/path")'`, f.workspace);
    assert.deepEqual(sourceWithDynamicSyntax.reasons, ["Opaque lua inline code requires approval"]);
    assert.deepEqual(sourceWithDynamicSyntax.pathExpansions ?? [], []);
    assert.equal(f.analyzer.analyzeCommand("then luac -p .config/hypr/lua/*.lua", f.workspace).decision, "allow");
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
    assert.equal(f.analyzer.analyzeCommand("trap 'echo safe' EXIT", f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand("trap -p EXIT", f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand("trap 'unknown-deferred-command' EXIT", f.workspace).decision, "ask");
    assert.equal(f.analyzer.analyzeCommand("builtin printf safe", f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand("builtin eval unknown-deferred-command", f.workspace).decision, "ask");
    assert.equal(f.analyzer.analyzeCommand("let 'value = 1 + 2'", f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand("getopts ab option", f.workspace).decision, "allow");
    assert.equal(f.analyzer.analyzeCommand(`[[ -f ${join(f.workspace, "missing")} ]]`, f.workspace).decision, "allow");
    writeFileSync(join(f.workspace, ".env"), "TOKEN=test\n");
    assert.equal(f.analyzer.analyzeCommand(`[[ -f ${join(f.workspace, ".env")} ]]`, f.workspace).decision, "deny");
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

    const store = join(f.systemReadonly, "assigned-store-path");
    const resolved = f.analyzer.analyzeCommandUnits(`store=${store}; nix build "$store"`, f.workspace)
      .filter((unit) => unit.analysis.decision !== "allow");
    assert.deepEqual(resolved[0]?.resolvedBindings, [{ name: "store", value: store }]);

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

test("Node, Python, and Julia inline source is parsed while other runtimes remain opaque", () => {
  const f = fixture();
  try {
    const grouped = `for p in "${f.workspace}"; do (cd "$p" && node -e 'console.log(\`cwd: \${process.cwd()}\`)'); done`;
    const requiring = f.analyzer.analyzeCommandUnits(grouped, f.workspace)
      .filter((unit) => unit.analysis.decision !== "allow");
    assert.equal(requiring.length, 0);

    assert.equal(f.analyzer.analyzeCommand(`bash -lc "printf safe"`, f.workspace).decision, "allow");
    for (const command of [
      `node --eval 'console.log("safe")'`,
      `python -c 'print("safe")'`,
    ]) assert.equal(f.analyzer.analyzeCommand(command, f.workspace).decision, "allow", command);

    for (const command of [
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
    const missingArgument = join(f.workspace, "missing-input.txt");
    const missingPath = f.analyzer.analyzeCommand(`inspect-local --json ${missingArgument}`, f.workspace);
    assert.equal(missingPath.decision, "allow");
    assert.deepEqual(missingPath.ownershipCandidates, []);
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
