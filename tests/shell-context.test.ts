import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, symlinkSync } from "node:fs";
import { execFileSync, spawnSync } from "node:child_process";
import { join } from "node:path";
import { GuardAnalyzer } from "../analyzer.ts";
import { PolicyStore } from "../policy.ts";
import { captureBashContext, verifyBashContext, INHERITED_PATH_VARIABLES } from "../bash-context.ts";
import { initialShellEnvironment, resolveShellParameter, shellValue, type ShellEnvironment } from "../shell-context.ts";

function fixture() {
  const root = mkdtempSync("/tmp/bash-guard-shell-context-");
  const workspace = join(root, "workspace");
  const home = join(root, "home");
  const extension = join(root, "extension");
  const cache = join(root, "cache");
  const child = join(workspace, "child");
  const system = join(root, "store");
  for (const path of [workspace, home, extension, cache, child, system]) {
    mkdirSync(path); writeFileSync(join(path, "value.txt"), "fixture");
  }
  const policy = new PolicyStore(extension, workspace, home, [system]);
  const analyzer = new GuardAnalyzer(policy);
  const inherited = { HOME: home, PWD: workspace, TMPDIR: cache, XDG_CACHE_HOME: cache, XDG_CONFIG_HOME: home };
  const run = (command: string, environment: ShellEnvironment = inherited) => analyzer.analyzeCommandUnits(command, workspace, "direct", workspace, environment);
  return { root, workspace, home, cache, child, system, policy, analyzer, inherited, run, cleanup: () => execFileSync("gio", ["trash", "--", root]) };
}

function reasons(units: ReturnType<GuardAnalyzer["analyzeCommandUnits"]>): string {
  return units.flatMap((unit) => unit.analysis.reasons).join("\n");
}

function paths(units: ReturnType<GuardAnalyzer["analyzeCommandUnits"]>): string[] {
  return units.flatMap((unit) => unit.analysis.accesses.map((access) => access.path));
}

test("shell scalar resolution distinguishes known, unset, unknown, and runtime-only parameters", () => {
  const environment = initialShellEnvironment("/tmp/bash-guard-fixture", "/tmp/bash-guard-home", { empty: "", absent: undefined, value: "leaf", RANDOM: "123", constructor: "data" });
  assert.equal(shellValue(environment, "absent"), "");
  assert.equal(shellValue(environment, "missing"), undefined);
  assert.equal(shellValue(environment, "toString"), undefined);
  assert.equal(resolveShellParameter("constructor", environment), "data");
  for (const [expression, expected] of [
    ["absent:-fallback", "fallback"], ["empty:-fallback", "fallback"], ["empty-fallback", ""],
    ["value:+alternate", "alternate"], ["empty+alternate", "alternate"], ["absent+alternate", ""],
    ["value:-fallback", "leaf"], ["absent:-$value/path", "leaf/path"],
  ]) assert.equal(resolveShellParameter(expression!, environment), expected);
  for (const expression of ["missing:-fallback", "value:=side-effect", "!value", "value%pattern", "RANDOM", "$", "!", "1"]) {
    assert.match(resolveShellParameter(expression, environment), /^\$/);
  }
});

test("generic assignments propagate aliases, ordered RHS values, declarations, defaults, and overrides", () => {
  const f = fixture();
  try {
    for (const command of [
      'a="$XDG_CACHE_HOME" b="$a"; cat "$b/value.txt"',
      'export a="$TMPDIR"; readonly b="$a"; cat "$b/value.txt"',
      'declare -x a="$XDG_CACHE_HOME"; b="$a"; cat "${b}/value.txt"',
      'unset a; a="${a:-$XDG_CACHE_HOME}"; cat "$a/value.txt"',
      `a=${f.home}; a=${f.cache}; cat "$a/value.txt"`,
    ]) {
      const units = f.run(command);
      assert.equal(units.at(-1)!.analysis.decision, "allow", reasons(units));
      assert.ok(paths(units).includes(join(f.cache, "value.txt")), command);
    }
    const reassignedHome = f.run(`HOME=${f.cache}; cat ~/value.txt`);
    assert.deepEqual(paths(reassignedHome).slice(-1), [join(f.cache, "value.txt")]);
    const builtinExpansion = f.run(`a=${f.cache}; export a=${f.home} b="$a"; cat "$b/value.txt"`);
    assert.ok(paths(builtinExpansion).includes(join(f.cache, "value.txt")));
    const redirected = f.run(`a=${f.home}; a=${f.cache} > ${join(f.workspace, "output")}; cat "$a/value.txt"`);
    assert.ok(paths(redirected).includes(join(f.cache, "value.txt")));
    const prototypeName = f.run(`__proto__=${f.cache}; cat "$__proto__/value.txt"`);
    assert.ok(paths(prototypeName).includes(join(f.cache, "value.txt")));
    const append = f.run(`a=${f.root}; a+=/cache; cat "$a/value.txt"`);
    assert.equal(append.at(-1)!.analysis.decision, "allow", reasons(append));
    assert.ok(paths(append).includes(join(f.cache, "value.txt")));
  } finally { f.cleanup(); }
});

test("runtime writes invalidate old values without reviving an inherited binding", () => {
  const f = fixture();
  try {
    for (const update of [
      'base=$(printf runtime)', 'read base', 'printf -v base "%s" runtime',
      'declare -n base=reference', 'declare -a base', 'base=$RANDOM', 'unset base; : "${base:=runtime}"',
      'command export base=runtime', 'command -p read base', 'input=runtime read base',
      'printf -v "$dynamic_name" "%s" runtime', 'unset "$dynamic_name"', 'export "$runtime_assignment"',
      'base[0]=runtime', 'let "base=7"', ': "$((base=7))"', '((base=7))',
      'declare -n reference=base; reference=runtime', 'declare -i base; base=7',
    ]) {
      const units = f.run(`base=${f.cache}; ${update}; cat "$base/value.txt"`);
      assert.equal(units.at(-1)!.analysis.decision, "ask", `${update}: ${reasons(units)}`);
      assert.deepEqual(units.at(-1)!.resolvedBindings, undefined);
    }
    const unset = f.run('unset XDG_CACHE_HOME; cat "${XDG_CACHE_HOME:-$HOME}/value.txt"');
    assert.ok(paths(unset).includes(join(f.home, "value.txt")));
    const readonly = f.run(`readonly base=${f.cache}; unset base; base=${f.home}; cat "$base/value.txt"`);
    assert.ok(paths(readonly).includes(join(f.cache, "value.txt")));
    const noOpDefault = f.run(`base=${f.cache}; : "\${base:=runtime}"; cat "$base/value.txt"`);
    assert.ok(paths(noOpDefault).includes(join(f.cache, "value.txt")));
    const bare = f.run('cat "$UNPROVEN"');
    assert.equal(bare.at(-1)!.analysis.decision, "ask");
  } finally { f.cleanup(); }
});

test("quoted scalar paths remain concrete while unsafe unquoted splitting or globbing stays unresolved", () => {
  const f = fixture();
  try {
    const spaced = join(f.root, "directory with spaces");
    mkdirSync(spaced); writeFileSync(join(spaced, "value.txt"), "fixture");
    const quoted = f.run('cat "$BASE/value.txt"', { BASE: spaced });
    assert.equal(quoted.at(-1)!.analysis.decision, "allow", reasons(quoted));
    assert.deepEqual(paths(quoted), [join(spaced, "value.txt")]);
    for (const command of ['cat $BASE/value.txt', 'unset IFS; cat $BASE/value.txt', 'IFS=/; cat $XDG_CACHE_HOME/value.txt', 'unset missing; cat ${missing:-$BASE}/value.txt']) {
      assert.equal(f.run(command, { ...f.inherited, BASE: spaced }).at(-1)!.analysis.decision, "ask");
    }
    const tilde = join(f.workspace, "~"); mkdirSync(tilde); writeFileSync(join(tilde, "value.txt"), "fixture");
    for (const command of ["cat '~/value.txt'", 'base="~/value.txt"; cat "$base"']) {
      assert.deepEqual(paths(f.run(command)).slice(-1), [join(tilde, "value.txt")], "literal or expanded data must not undergo tilde expansion again");
    }
    assert.equal(f.run('unset HOME; cat ~/value.txt').at(-1)!.analysis.decision, "ask");
    assert.equal(f.run('cat "$BASE/value.txt"', { BASE: join(f.root, "*") }).at(-1)!.analysis.decision, "allow");
    assert.equal(f.run('cat $BASE/value.txt', { BASE: join(f.root, "*") }).at(-1)!.analysis.decision, "ask");
    const literal = f.run("printf '%s' '$UNPROVEN/value.txt'");
    assert.deepEqual(literal.at(-1)!.resolvedBindings, undefined);
  } finally { f.cleanup(); }
});

test("child scopes do not leak assignments and substitutions retain concrete effect screening", () => {
  const f = fixture();
  try {
    for (const child of [
      `(base=${f.home}; cat "$base/value.txt")`,
      `base=${f.home} printf child`,
      `base=${f.home} &`,
      `base=${f.home} | cat`,
      `value=$(base=${f.home}; printf child)`,
    ]) {
      const units = f.run(`base=${f.cache}; ${child}${child.endsWith("&") ? "" : ";"} cat "$base/value.txt"`);
      assert.deepEqual(units.at(-1)!.analysis.accesses.map((access) => access.path), [join(f.cache, "value.txt")], child);
    }
    const readonlyChild = f.run(`readonly base=${f.cache}; (base=${f.home}; cat "$base/value.txt")`);
    assert.ok(paths(readonlyChild).includes(join(f.cache, "value.txt")));
    assert.equal(paths(readonlyChild).includes(join(f.home, "value.txt")), false);
    const nested = f.run('value=$(cd child; cat "$PWD/value.txt"); cat "$PWD/value.txt"');
    assert.ok(paths(nested).includes(join(f.child, "value.txt")));
    assert.deepEqual(nested.at(-1)!.analysis.accesses.map((access) => access.path), [join(f.workspace, "value.txt")]);
    writeFileSync(join(f.child, ".env"), "fixture-secret");
    assert.equal(f.run('value=$(cd child; cat "$PWD/.env")')[0]!.analysis.decision, "deny");
  } finally { f.cleanup(); }
});

test("conditional alternatives retain concrete denials and uncertain directory changes are not guessed", () => {
  const f = fixture();
  try {
    writeFileSync(join(f.cache, ".env"), "fixture-secret");
    const branch = f.run(`base=${f.home}; if test -f condition; then base=${f.cache}; else base=${f.home}; fi; cat "$base/.env"`);
    assert.ok(branch.some((unit) => unit.analysis.decision === "deny"), reasons(branch));
    const partialAlias = f.run(`if test -f condition; then base=${f.cache}; else base=$RANDOM; fi; alias="$base"; cat "$alias/.env"`);
    assert.ok(partialAlias.some((unit) => unit.analysis.decision === "deny"), reasons(partialAlias));
    const conditional = f.run(`base=${f.home}; test -f condition && base=${f.cache}; cat "$base/value.txt"`);
    assert.ok(paths(conditional).includes(join(f.home, "value.txt")));
    assert.ok(paths(conditional).includes(join(f.cache, "value.txt")));
    const unknownCd = f.run('cd "$DYNAMIC"; touch relative.txt');
    assert.equal(unknownCd.at(-1)!.analysis.decision, "ask");
    assert.deepEqual(unknownCd.at(-1)!.analysis.creationCandidates, []);
    const recovered = f.run(`cd "$DYNAMIC"; cd ${f.cache}; cat "$PWD/value.txt"`);
    assert.equal(recovered.at(-1)!.analysis.decision, "allow", reasons(recovered));
    for (const cd of ['cd child > /dev/null', 'command -p cd child', 'builtin cd child']) {
      const redirected = f.run(`${cd}; cat "$PWD/value.txt"`);
      assert.deepEqual(paths(redirected).slice(-1), [join(f.child, "value.txt")]);
    }
    assert.equal(f.run('HOME="$XDG_CACHE_HOME" cd; touch relative.txt').at(-1)!.analysis.decision, "ask");
    for (const update of ['pushd child', 'popd', 'set -P']) {
      assert.equal(f.run(`${update}; cat "$PWD/value.txt"`).at(-1)!.analysis.decision, "ask", update);
    }
    const pipeline = f.run('base="$XDG_CACHE_HOME"; printf x | read base; cat "$base/value.txt"');
    assert.ok(pipeline.some((unit) => unit.analysis.decision === "ask"), reasons(pipeline));
  } finally { f.cleanup(); }
});

test("directory variables, saved aliases, and logical/physical cd are distinct shell facts", () => {
  const f = fixture();
  try {
    const nested = join(f.cache, "nested"); mkdirSync(nested); writeFileSync(join(nested, "value.txt"), "fixture");
    const link = join(f.workspace, "link"); symlinkSync(nested, link);
    const saved = f.run('saved="$PWD"; cd child; cat "$saved/value.txt" "$PWD/value.txt" "$OLDPWD/value.txt"');
    assert.deepEqual(saved.at(-1)!.analysis.accesses.map((access) => access.path), [join(f.workspace, "value.txt"), join(f.child, "value.txt"), join(f.workspace, "value.txt")]);
    const logical = f.run('cd ./link; cd ..; cat "$PWD/value.txt"');
    assert.deepEqual(paths(logical).slice(-1), [join(f.workspace, "value.txt")]);
    const physical = f.run('cd ./link; cd -P ..; cat "$PWD/value.txt"');
    assert.deepEqual(paths(physical).slice(-1), [join(f.cache, "value.txt")]);
    const physicalOperand = f.run('cd -P ./link/..; cat "$PWD/value.txt"');
    assert.deepEqual(paths(physicalOperand).slice(-1), [join(f.cache, "value.txt")]);
    assert.equal(f.run('cd -P ./missing/../child; touch relative.txt').at(-1)!.analysis.decision, "ask");
    const expandedAlias = f.run(`base=${link}; cat "$base/../value.txt"`);
    assert.deepEqual(paths(expandedAlias).slice(-1), [join(f.cache, "value.txt")]);
    const back = f.run('cd child; cd -; cat "$PWD/value.txt"');
    assert.deepEqual(paths(back).slice(-1), [join(f.workspace, "value.txt")]);
    const alias = join(f.cache, "workspace-alias"); symlinkSync(f.workspace, alias);
    const overridden = f.run(`PWD=${alias}; cd child; cd ..; cat "$PWD/value.txt"`);
    assert.deepEqual(overridden.at(-1)!.resolvedBindings, [{ name: "PWD", value: f.workspace }]);
    const readonly = f.run('readonly PWD; cd child; cat "$PWD/value.txt" ./value.txt');
    assert.deepEqual(readonly.at(-1)!.analysis.accesses.map((access) => access.path), [join(f.workspace, "value.txt"), join(f.child, "value.txt")]);
  } finally { f.cleanup(); }
});

test("inherited path snapshots are bounded, explicit, immutable, and never inspect arbitrary secrets", () => {
  const f = fixture();
  try {
    const command = 'cat "$XDG_CACHE_HOME/value.txt" "${XDG_STATE_HOME:-$HOME}/value.txt" "$API_TOKEN/value.txt"';
    const inherited = new Proxy({ ...f.inherited }, {
      get(target, key: string) {
        assert.ok(["PWD", "CDPATH", ...INHERITED_PATH_VARIABLES].includes(key), `unexpected inherited lookup: ${key}`);
        return target[key as keyof typeof target];
      },
    });
    const snapshot = captureBashContext(command, f.workspace, f.home, inherited);
    assert.equal(snapshot.environment.XDG_STATE_HOME, undefined);
    assert.ok(Object.hasOwn(snapshot.environment, "XDG_STATE_HOME"));
    inherited.XDG_CACHE_HOME = f.home;
    assert.equal(snapshot.environment.XDG_CACHE_HOME, f.cache, "a later environment change cannot alter the approved snapshot");
    assert.equal(captureBashContext(command, f.workspace, f.home, inherited).environment.XDG_CACHE_HOME, f.home);
    assert.equal(Object.hasOwn(snapshot.environment, "API_TOKEN"), false);
    assert.equal(Object.isFrozen(snapshot.environment), true);
    assert.equal(Object.isFrozen(snapshot.assertions), true);
    const units = f.run(command, { ...snapshot.environment });
    assert.ok(paths(units).includes(join(f.cache, "value.txt")));
    assert.match(reasons(units), /API_TOKEN/);
    const rejected = captureBashContext('cat "$XDG_CACHE_HOME/value.txt"', f.workspace, f.home, { ...f.inherited, XDG_CACHE_HOME: "private-credential-value" });
    assert.equal(JSON.stringify(rejected).includes("private-credential-value"), false);
    assert.equal(verifyBashContext(command, rejected).includes("private-credential-value"), false);
  } finally { f.cleanup(); }
});

test("resolved inherited paths still enforce secrets, ownership, metadata, and system denials", () => {
  const f = fixture();
  try {
    writeFileSync(join(f.cache, ".env"), "fixture-secret");
    mkdirSync(join(f.cache, ".git")); writeFileSync(join(f.cache, ".git", "config"), "fixture");
    for (const command of ['cat "$XDG_CACHE_HOME/.env"', 'rm "$XDG_CACHE_HOME/value.txt"', 'printf changed > "$XDG_CACHE_HOME/.git/config"']) {
      assert.equal(f.run(command).at(-1)!.analysis.decision, "deny", command);
    }
    assert.equal(f.run('touch "$XDG_CACHE_HOME/value.txt"').at(-1)!.analysis.decision, "ask");
    assert.equal(f.run('touch "$XDG_CACHE_HOME/value.txt"', { XDG_CACHE_HOME: f.system }).at(-1)!.analysis.decision, "deny");
    const reportShape = f.run('audit=$(mktemp -d); nix flake metadata --json --no-write-lock-file "path:$PWD/project" > "$audit/metadata.json"');
    assert.deepEqual(reportShape.at(-1)!.analysis.reasons, ["nix may mutate remote or managed state"]);
    assert.deepEqual(reportShape[0]!.analysis.creationPatterns, [join(f.cache, "tmp.*")]);
  } finally { f.cleanup(); }
});

test("shell context inspection limits fail closed and reset for the next call", () => {
  const f = fixture();
  try {
    const deep = f.run("( ".repeat(40) + "printf child" + " )".repeat(40));
    assert.match(reasons(deep), /inspection limit/);
    const long = f.run(Array.from({ length: 1025 }, () => ":").join("; "));
    assert.match(reasons(long), /1024 command units/);
    assert.equal(f.run('cat "$PWD/value.txt"').at(-1)!.analysis.decision, "allow");
  } finally { f.cleanup(); }
});

test("runtime verification stops stale environments/cwds before the submitted command, without changing values", () => {
  const f = fixture();
  try {
    // Only these harmless printf commands execute. Hazard fixtures above are analysis-only.
    const command = 'printf "%s" "$XDG_CACHE_HOME"';
    const snapshot = captureBashContext(command, f.workspace, f.home, f.inherited);
    const script = verifyBashContext(command, snapshot);
    const env = { PATH: process.env.PATH, ...f.inherited };
    const matched = spawnSync("bash", ["--noprofile", "--norc", "-c", script], { cwd: f.workspace, env, encoding: "utf8" });
    assert.equal(matched.status, 0, matched.stderr);
    assert.equal(matched.stdout, f.cache);
    for (const options of [
      { cwd: f.workspace, env: { ...env, XDG_CACHE_HOME: f.home } },
      { cwd: f.child, env },
      { cwd: f.workspace, env: { ...env, CDPATH: f.home } },
    ]) {
      const result = spawnSync("bash", ["--noprofile", "--norc", "-c", script], { ...options, encoding: "utf8" });
      assert.equal(result.status, 125, result.stderr);
      assert.equal(result.stdout, "");
      assert.match(result.stderr, /context changed/);
    }
    for (const prefix of [
      'readonly XDG_CACHE_HOME',
      'declare -a XDG_CACHE_HOME=("$XDG_CACHE_HOME")',
      '__fixture_target="$XDG_CACHE_HOME"; declare -n XDG_CACHE_HOME=__fixture_target',
      'IFS=/',
      'set -P',
      'set -o posix',
    ]) {
      const result = spawnSync("bash", ["--noprofile", "--norc", "-c", `${prefix};\n${script}`], { cwd: f.workspace, env, encoding: "utf8" });
      assert.equal(result.status, 125, `${prefix}: ${result.stderr}`);
      assert.equal(result.stdout, "");
    }
    const marker = join(f.root, "must-not-exist");
    const hostileValue = `${f.cache}/$(touch ${marker})`;
    const opaque = captureBashContext('cat "$XDG_CACHE_HOME/value.txt"', f.workspace, f.home, { ...env, XDG_CACHE_HOME: hostileValue });
    assert.equal(JSON.stringify(opaque).includes(hostileValue), false);
    assert.equal(existsSync(marker), false);
    const missing = captureBashContext('printf "%s" "${XDG_STATE_HOME:-fallback}"', f.workspace, f.home, env);
    const changed = spawnSync("bash", ["-c", verifyBashContext('printf ran', missing)], { cwd: f.workspace, env: { ...env, XDG_STATE_HOME: "" }, encoding: "utf8" });
    assert.equal(changed.status, 125);
    assert.equal(changed.stdout, "");
  } finally { f.cleanup(); }
});
