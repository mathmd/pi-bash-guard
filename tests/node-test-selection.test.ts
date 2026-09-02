import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { selectNodeTestFiles } from "../node-test-selection.ts";

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "bash-guard-node-tests-"));
  const files = {
    named: join(root, "named.test.ts"),
    nested: join(root, "test", "helper.ts"),
    ordinary: join(root, "ordinary.ts"),
    ignored: join(root, "node_modules", "ignored.test.ts"),
  };
  mkdirSync(join(root, "test"), { recursive: true });
  mkdirSync(join(root, "node_modules"), { recursive: true });
  for (const path of Object.values(files)) writeFileSync(path, "export {};\n");
  return { root, files, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

test("node test discovery resolves default tests without node_modules", () => {
  const f = fixture();
  try {
    const selection = selectNodeTestFiles(["--test"], f.root);
    assert.equal(selection.enabled, true);
    assert.deepEqual(selection.files, [f.files.named, f.files.nested].sort());
    assert.equal(selection.truncated, false);
    assert.deepEqual(selectNodeTestFiles(["--test", "*.test.ts"], f.root).files, [f.files.named]);
  } finally { f.cleanup(); }
});

test("node test selection distinguishes option values from explicit targets", () => {
  const f = fixture();
  try {
    const report = join(f.root, "report.txt");
    const setup = join(f.root, "setup.ts");
    writeFileSync(setup, "export {};\n");
    const selection = selectNodeTestFiles([
      "--test", "--test-name-pattern", "forced push", "--test-global-setup", setup,
      `--test-reporter-destination=${report}`, f.files.named,
    ], f.root);
    assert.deepEqual(selection.files, [f.files.named]);
    assert.deepEqual(selection.supportFiles, [setup]);
    assert.deepEqual(selection.reporterDestinations, [report]);
    assert.equal(selectNodeTestFiles(["--test", "$runtime"], f.root).unresolved, true);
    assert.equal(selectNodeTestFiles([f.files.ordinary, "--test"], f.root).enabled, false);
  } finally { f.cleanup(); }
});

test("an explicit node test directory is inspected recursively", () => {
  const f = fixture();
  try {
    const selection = selectNodeTestFiles(["--test", f.root], f.root);
    assert.deepEqual(selection.files, [f.files.named, f.files.nested, f.files.ordinary].sort());
  } finally { f.cleanup(); }
});

test("node test discovery is bounded", () => {
  const root = mkdtempSync(join(tmpdir(), "bash-guard-node-test-limit-"));
  try {
    for (let index = 0; index < 513; index++) writeFileSync(join(root, `case-${index}.test.js`), "export {};\n");
    const selection = selectNodeTestFiles(["--test"], root);
    assert.equal(selection.files.length, 512);
    assert.equal(selection.truncated, true);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
