import test from "node:test";
import assert from "node:assert/strict";
import { displayHeredocOperators, extractShellHeredocs, heredocHasDynamicExpansion } from "../shell-heredoc.ts";

test("quoted heredoc bodies are attached to their command rather than parsed as shell", () => {
  const source = `cd /tmp && node --input-type=module - <<'NODE'\nimport { parse } from "@babel/parser";\nconsole.log("git push --force");\nNODE\necho done`;
  const extracted = extractShellHeredocs(source);
  assert.equal(extracted.error, undefined);
  assert.doesNotMatch(extracted.command, /import \{ parse \}/);
  const heredoc = [...extracted.heredocs.values()][0]!;
  assert.match(heredoc.source, /^import \{ parse \}/);
  assert.equal(heredoc.quotedDelimiter, true);
  assert.equal(heredocHasDynamicExpansion(heredoc), false);
  assert.match(displayHeredocOperators(extracted.command, extracted.heredocs), /<<'NODE'/);
});

test("multiple heredocs preserve order and tab stripping", () => {
  const extracted = extractShellHeredocs("cat <<A <<-'B'\none\nA\n\ttwo\n\tB\n");
  assert.equal(extracted.error, undefined);
  assert.deepEqual([...extracted.heredocs.values()].map(({ source }) => source), ["one\n", "two\n"]);
});

test("missing and dynamically expanded heredocs fail closed", () => {
  assert.match(extractShellHeredocs("node <<EOF\ncode\n").error ?? "", /not found/);
  const extracted = extractShellHeredocs("node <<EOF\nconsole.log($RUNTIME)\nEOF\n");
  assert.equal(heredocHasDynamicExpansion([...extracted.heredocs.values()][0]!), true);
  assert.equal(extractShellHeredocs("echo $((1 << 2))\n").heredocs.size, 0);
  assert.equal(extractShellHeredocs("cat <<< value\n").heredocs.size, 0);
});
