import test from "node:test";
import assert from "node:assert/strict";
import { builtinCommandCategory, SHELL_CLOSING_WORDS, SHELL_PREFIX_WORDS } from "../command-catalog.ts";

test("common shell and Unix commands have conservative categories", () => {
  assert.equal(builtinCommandCategory("set"), "allow");
  assert.equal(builtinCommandCategory("tee"), "edit");
  assert.equal(builtinCommandCategory("cat"), "read");
  assert.equal(builtinCommandCategory("mkdir"), "create");
  assert.equal(builtinCommandCategory("xargs"), "execute");
  assert.equal(builtinCommandCategory("curl"), "remote");
  assert.equal(builtinCommandCategory("shred"), "deny");
  assert.equal(builtinCommandCategory("not-registered"), undefined);
});

test("shell structural words are distinguished from closing words", () => {
  assert.equal(SHELL_PREFIX_WORDS.has("if"), true);
  assert.equal(SHELL_PREFIX_WORDS.has("then"), true);
  assert.equal(SHELL_CLOSING_WORDS.has("fi"), true);
  assert.equal(SHELL_CLOSING_WORDS.has("then"), false);
});
