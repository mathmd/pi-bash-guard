import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { GuardAnalyzer } from "../analyzer.ts";
import { genericPathInputs } from "../tool-paths.ts";
import { PolicyStore } from "../policy.ts";

test("configured read-only tools use read access while retaining secret checks", () => {
  const root = mkdtempSync(join(tmpdir(), "bash-guard-tool-analysis-"));
  try {
    const extension = join(root, "extension");
    const workspace = join(root, "workspace");
    const home = join(root, "home");
    mkdirSync(extension); mkdirSync(workspace); mkdirSync(home);
    const policy = new PolicyStore(extension, workspace, home);
    const analyzer = new GuardAnalyzer(policy);
    const analyze = (path: string) => {
      const [access] = genericPathInputs(
        { pattern: "example", path },
        "",
        [],
        policy.isReadOnlyTool("anchor_grep") ? "read" : undefined,
      );
      assert.ok(access);
      return { kind: access.kind, analysis: analyzer.analyzePathAccess(access.value, access.kind, workspace, "anchor_grep") };
    };

    const before = analyze(workspace);
    assert.equal(before.kind, "unknown");
    assert.equal(before.analysis.decision, "ask");
    policy.save("local", {
      version: 3,
      ownership: { edit: [], execute: [], full: [] },
      secrets: [],
      commands: { include: [], exclude: [] },
      tools: { read: ["anchor_grep"] },
    });
    const after = analyze(workspace);
    assert.equal(after.kind, "read");
    assert.equal(after.analysis.decision, "allow");

    const secret = join(workspace, ".env");
    writeFileSync(secret, "TOKEN=test\n");
    assert.equal(analyze(secret).analysis.decision, "deny");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
