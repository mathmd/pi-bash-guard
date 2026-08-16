import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { editorInvocation } from "../external-editor.ts";
import { detailViewport } from "../ui.ts";

test("Neovim opens the policy at the newly appended entry", () => {
  const root = mkdtempSync(join(tmpdir(), "bash-guard-editor-"));
  try {
    const path = join(root, "policy.json");
    assert.deepEqual(editorInvocation("nvim", path, 12), {
      command: "nvim",
      args: ["+12", path],
    });
    assert.deepEqual(editorInvocation("code --wait", path, 7), {
      command: "code",
      args: ["--wait", "--goto", `${path}:7:1`],
    });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("long permission details remain scrollable while reserving option rows", () => {
  const text = Array.from({ length: 30 }, (_, index) => `reason ${index + 1}`).join("\n");
  const first = detailViewport(text, 80, 12, 3, 0);
  const last = detailViewport(text, 80, 12, 3, Number.MAX_SAFE_INTEGER);
  assert.equal(first.total, 30);
  assert.ok(first.pageSize < first.total);
  assert.deepEqual(first.lines, ["reason 1", "reason 2"]);
  assert.deepEqual(last.lines, ["reason 29", "reason 30"]);
  assert.equal(last.offset + last.lines.length, last.total);
});
