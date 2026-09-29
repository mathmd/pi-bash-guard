import test from "node:test";
import assert from "node:assert/strict";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { registerPermissionDiscussion } from "../permission-discussion.ts";

function harness() {
  const handlers = new Map<string, (event: Record<string, unknown>, ctx: ExtensionContext) => unknown>();
  const messages: Array<{ text: string; options: unknown }> = [];
  const notifications: string[] = [];
  const statuses = new Map<string, string | undefined>();
  let failSend = false;
  const pi = {
    on: (name: string, handler: (event: Record<string, unknown>, ctx: ExtensionContext) => unknown) => handlers.set(name, handler),
    sendUserMessage: (text: string, options: unknown) => {
      if (failSend) throw new Error("fixture dispatch failure");
      messages.push({ text, options });
    },
    setActiveTools: () => assert.fail("discussion must not overwrite other extensions' active tools"),
    appendEntry: () => assert.fail("discussion must not persist grants or state"),
  } as unknown as ExtensionAPI;
  const ctx = {
    ui: {
      theme: { fg: (_color: string, text: string) => text },
      setStatus: (name: string, value: string | undefined) => statuses.set(name, value),
      notify: (message: string) => notifications.push(message),
    },
  } as unknown as ExtensionContext;
  const discussion = registerPermissionDiscussion(pi);
  return { discussion, ctx, messages, statuses, notifications,
    failSend: () => { failSend = true; },
    emit: (name: string, fields: Record<string, unknown> = {}) => handlers.get(name)?.({ type: name, ...fields }, ctx),
  };
}

test("discussion releases the deferring batch to the model, then holds tool retries until human input", () => {
  const h = harness();
  assert.equal(h.discussion.blockedCall(), undefined);
  h.emit("turn_start");
  const result = h.discussion.defer("Why this operation?", h.ctx);
  assert.equal(result.block, true);
  assert.equal(result.terminate, false, "the question must still receive a model response");
  assert.match(result.reason!, /not approved or refused/);
  assert.match(result.reason!, /Why this operation\?/);
  assert.deepEqual(h.messages, [{ text: "Why this operation?", options: { deliverAs: "steer" } }]);
  assert.match(h.statuses.get("bash-guard-discussion")!, /reply to continue/);
  assert.equal(h.discussion.blockedCall()?.terminate, false, "remaining sibling preflights do not ask again");

  h.emit("input", { source: "extension" });
  h.emit("turn_start");
  assert.equal(h.discussion.blockedCall()?.terminate, true, "a tool-only discussion retry stops rather than looping");
  for (const event of ["agent_end", "agent_settled", "session_compact"]) h.emit(event);
  assert.equal(h.discussion.blockedCall()?.block, true);
  h.emit("input", { source: "interactive" });
  assert.equal(h.discussion.blockedCall()?.block, true, "an in-flight discussion turn cannot execute its old plan after a reply");
  h.emit("turn_start");
  assert.equal(h.discussion.blockedCall(), undefined);
  assert.equal(h.statuses.get("bash-guard-discussion"), undefined);
});

test("an early human reply cannot release old sibling calls; RPC replies also resume fresh checks", () => {
  const h = harness();
  h.emit("turn_start");
  h.discussion.defer("Use a safer plan.", h.ctx);
  h.emit("input", { source: "rpc" });
  assert.equal(h.discussion.blockedCall()?.block, true);
  assert.equal(h.discussion.blockedCall()?.terminate, false);
  h.emit("turn_start");
  assert.equal(h.discussion.blockedCall(), undefined);
});

test("discussion state resets on session replacement, is instance-local, and fails closed on dispatch errors", () => {
  const h = harness();
  for (const reason of ["startup", "reload", "new", "resume", "fork"]) {
    h.discussion.defer("Question", h.ctx);
    h.emit("session_start", { reason });
    assert.equal(h.discussion.blockedCall(), undefined);
    assert.equal(h.statuses.get("bash-guard-discussion"), undefined);
  }
  h.failSend();
  const failed = h.discussion.defer("Retain this question even if dispatch fails.", h.ctx);
  assert.equal(failed.block, true);
  assert.equal(failed.terminate, false);
  assert.match(failed.reason!, /Retain this question/);
  assert.match(h.notifications.at(-1)!, /remains deferred/);
  assert.equal(h.discussion.blockedCall()?.block, true);
  assert.equal(harness().discussion.blockedCall(), undefined);
  h.emit("session_shutdown", { reason: "reload" });
  assert.equal(h.discussion.blockedCall(), undefined);
});
