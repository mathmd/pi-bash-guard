import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { canonicalPath, globToRegExp, isWithin } from "../path-utils.ts";

test("canonical path follows fixture-local symlinks and preserves missing suffix", () => {
  const root = mkdtempSync(join(tmpdir(), "bash-guard-path-"));
  try {
    const real = join(root, "real");
    const link = join(root, "link");
    mkdirSync(real); symlinkSync(real, link);
    assert.equal(canonicalPath(join(link, "missing.txt")), join(real, "missing.txt"));
    assert.equal(isWithin(canonicalPath(join(link, "missing.txt")), real), true);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("glob supports recursive and single-component wildcards", () => {
  assert.equal(globToRegExp("/fixture/**/file?.txt").test("/fixture/a/b/file1.txt"), true);
  assert.equal(globToRegExp("/fixture/*.txt").test("/fixture/a/file.txt"), false);
});
