import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { selectNpmScripts } from "../npm-scripts.ts";

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "bash-guard-npm-scripts-"));
  const nested = join(root, "nested");
  mkdirSync(nested);
  writeFileSync(join(root, "package.json"), JSON.stringify({ scripts: {
    pretest: "printf pre",
    test: "node --test",
    posttest: "printf post",
  } }));
  return { root, nested, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

test("npm test resolves its package and lifecycle scripts in order", () => {
  const f = fixture();
  try {
    const selection = selectNpmScripts(["test", "--", "--test-only"], f.nested);
    assert.equal(selection.handled, true);
    assert.equal(selection.packageRoot, f.root);
    assert.deepEqual(selection.scripts, [
      { name: "pretest", source: "printf pre", appendArguments: false },
      { name: "test", source: "node --test", appendArguments: true },
      { name: "posttest", source: "printf post", appendArguments: false },
    ]);
    assert.deepEqual(selection.arguments, ["--test-only"]);
  } finally { f.cleanup(); }
});

test("npm run aliases and ignore-scripts select only static manifest entries", () => {
  const f = fixture();
  try {
    const run = selectNpmScripts(["run", "--silent", "test"], f.root);
    assert.equal(run.handled, true);
    assert.equal(run.scripts.length, 3);
    const ignored = selectNpmScripts(["--ignore-scripts", "t"], f.root);
    assert.deepEqual(ignored.scripts.map((script) => script.name), ["test"]);
    writeFileSync(join(f.root, "package.json"), JSON.stringify({ scripts: { prelint: "shutdown now" } }));
    assert.deepEqual(selectNpmScripts(["run", "lint"], f.root).scripts, []);
    assert.equal(selectNpmScripts(["install"], f.root).handled, false);
    const dynamic = selectNpmScripts(["run", "$SCRIPT"], f.root);
    assert.equal(dynamic.dynamicSelection, true);
    assert.match(dynamic.unresolvedReason ?? "", /script name/);
    assert.equal(selectNpmScripts(["--workspace", "$WORKSPACE", "test"], f.root).dynamicSelection, true);
    assert.equal(selectNpmScripts(["--script-shell", "$SHELL", "test"], f.root).dynamicSelection, true);
  } finally { f.cleanup(); }
});

test("npm workspace and malformed manifest selection fail closed", () => {
  const f = fixture();
  try {
    assert.match(selectNpmScripts(["--workspace", "app", "test"], f.root).unresolvedReason ?? "", /workspace/);
    assert.match(selectNpmScripts(["--script-shell", "python", "test"], f.root).unresolvedReason ?? "", /script shell/);
    writeFileSync(join(f.root, "package.json"), "not json\n");
    assert.match(selectNpmScripts(["test"], f.root).unresolvedReason ?? "", /could not be parsed/);
  } finally { f.cleanup(); }
});
