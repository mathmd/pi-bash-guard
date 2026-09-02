import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { editorInvocation } from "../external-editor.ts";
import type { PolicyStore } from "../policy.ts";
import { detailViewport, formatTimeout, ownershipGrantLevels, promptForDecision, shellBindingDetails, STEERING_CHOICE } from "../ui.ts";

interface PromptHarness {
  ctx: ExtensionContext;
  menus: string[][];
  editorTitles: string[];
  notifications: string[];
}

function promptHarness(selections: string[], editorValues: Array<string | undefined>): PromptHarness {
  const menus: string[][] = [];
  const editorTitles: string[] = [];
  const notifications: string[] = [];
  const ctx = {
    mode: "rpc",
    hasUI: true,
    ui: {
      select: async (_title: string, options: string[]) => {
        menus.push([...options]);
        const selection = selections.shift();
        assert.ok(selection, "test must provide a scripted menu selection");
        assert.ok(options.includes(selection), `${selection} must be present in the menu`);
        return selection;
      },
      editor: async (title: string) => {
        editorTitles.push(title);
        return editorValues.shift();
      },
      notify: (message: string) => notifications.push(message),
    },
  } as unknown as ExtensionContext;
  return { ctx, menus, editorTitles, notifications };
}

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

test("ownership prompts expose relevant capability grants and timeout labels", () => {
  const path = "/tmp/bash-guard-ui-target";
  const analysis = {
    decision: "ask" as const,
    reasons: [],
    accesses: [{ path, kind: "edit" as const }],
    creationCandidates: [],
    trashablePaths: [],
    ownershipCandidates: [{ path, required: "edit" as const }],
  };
  assert.deepEqual(ownershipGrantLevels(analysis, analysis.ownershipCandidates[0]!), ["edit", "full"]);
  assert.deepEqual(
    ownershipGrantLevels({ ...analysis, accesses: [{ path, kind: "unknown" }] }, analysis.ownershipCandidates[0]!),
    ["edit", "execute", "full"],
  );
  assert.deepEqual(
    ownershipGrantLevels(analysis, { path, required: "execute" }),
    ["execute", "full"],
  );
  assert.equal(formatTimeout(90_000), "1m30s");
  assert.equal(formatTimeout(45_000), "45s");
});

test("permission details show statically resolved shell values", () => {
  assert.equal(
    shellBindingDetails({
      command: "nix build $store",
      analysis: { decision: "ask", reasons: [], accesses: [], creationCandidates: [], trashablePaths: [], ownershipCandidates: [] },
      resolvedBindings: [{ name: "store", value: "/nix/store/example" }],
    }),
    '\n\nResolved shell variable:\n$store = "/nix/store/example"',
  );
});

test("permission details describe symbolic runtime paths without exposing markers", () => {
  const details = shellBindingDetails({
    command: 'git clone URL "$tmp/repo"',
    analysis: { decision: "ask", reasons: [], accesses: [], creationCandidates: [], trashablePaths: [], ownershipCandidates: [] },
    resolvedBindings: [{
      name: "tmp",
      value: "/tmp/.bash-guard-mktemp-tmp-marker",
      symbolic: "runtime directory created by mktemp under /tmp",
    }],
  });
  assert.match(details, /\$tmp = <runtime directory created by mktemp under \/tmp>/);
  assert.doesNotMatch(details, /\.bash-guard-mktemp/);
});

test("permission details list concrete shell glob matches", () => {
  const details = shellBindingDetails({
    command: "unknown-inspector scripts/*.lua",
    analysis: {
      decision: "ask", reasons: [], accesses: [], creationCandidates: [], trashablePaths: [], ownershipCandidates: [],
      pathExpansions: [{ expression: "scripts/*.lua", matches: ["/tmp/project/scripts/a.lua", "/tmp/project/scripts/b.lua"] }],
    },
  });
  assert.match(details, /Expanded shell path "scripts\/\*\.lua"/);
  assert.match(details, /\/tmp\/project\/scripts\/a\.lua/);
  assert.match(details, /\/tmp\/project\/scripts\/b\.lua/);
});

test("steering returns to the pending permission and comments use the multiline editor", async () => {
  const policy = {
    permissionTimeoutMs: () => 0,
    isPolicyPath: () => false,
  } as unknown as PolicyStore;
  const analysis = {
    decision: "ask" as const,
    reasons: ["Approval required"],
    accesses: [],
    creationCandidates: [],
    trashablePaths: [],
    ownershipCandidates: [],
  };
  const steering: string[] = [];
  const steerPrompt = promptHarness(
    [STEERING_CHOICE, STEERING_CHOICE, "Allow once"],
    ["  Why is this needed?  ", "Use the read-only alternative if possible."],
  );
  const allowed = await promptForDecision(
    steerPrompt.ctx,
    policy,
    analysis,
    "Pending command",
    undefined,
    undefined,
    (text) => { steering.push(text); },
  );
  assert.deepEqual(allowed, { action: "allow" });
  assert.deepEqual(steering, ["Why is this needed?", "Use the read-only alternative if possible."]);
  assert.equal(steerPrompt.menus.length, 3, "permission must be shown again after every steering message");
  assert.ok(steerPrompt.menus.every((choices) => choices.includes("Allow once") && choices.includes("Refuse")));
  assert.ok(steerPrompt.editorTitles.every((title) => /permission remains pending/.test(title)));
  assert.equal(steerPrompt.notifications.length, 2);
  assert.ok(steerPrompt.notifications.every((message) => /permission decision is still pending/.test(message)));

  const refusal = promptHarness(["Refuse", "Add comment…"], ["  Stop here.\nUse the safer command.  "]);
  const refused = await promptForDecision(refusal.ctx, policy, analysis, "Pending command");
  assert.deepEqual(refused, { action: "refuse", context: "Stop here.\nUse the safer command." });
  assert.deepEqual(refusal.editorTitles, ["Comment on refusal"]);

  const deniedSteering: string[] = [];
  const denyPrompt = promptHarness([STEERING_CHOICE, "Refuse", "Refuse without comment"], ["Explain the hard denial."]);
  const denied = await promptForDecision(
    denyPrompt.ctx,
    policy,
    { ...analysis, decision: "deny" },
    "Prohibited command",
    undefined,
    undefined,
    (text) => { deniedSteering.push(text); },
  );
  assert.deepEqual(denied, { action: "refuse" });
  assert.deepEqual(deniedSteering, ["Explain the hard denial."]);
  assert.ok(denyPrompt.menus[0]!.includes(STEERING_CHOICE));
  assert.ok(denyPrompt.menus[1]!.includes(STEERING_CHOICE));
});
