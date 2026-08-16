import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { editorInvocation } from "../external-editor.ts";

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
