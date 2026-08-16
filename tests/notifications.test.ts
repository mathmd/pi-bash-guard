import test from "node:test";
import assert from "node:assert/strict";
import { notificationInvocation } from "../notifications.ts";

test("system notification commands pass content as data, not shell source", () => {
  const title = 'Pi "attention"';
  const body = "command; $(unsafe)";

  const linux = notificationInvocation("linux", title, body)!;
  assert.equal(linux.command, "notify-send");
  assert.deepEqual(linux.args.slice(-2), [title, body]);

  const mac = notificationInvocation("darwin", title, body)!;
  assert.equal(mac.command, "osascript");
  assert.deepEqual(mac.args.slice(-2), [title, body]);

  const windows = notificationInvocation("win32", title, body, {})!;
  assert.equal(windows.command, "powershell.exe");
  assert.equal(windows.env?.PI_NOTIFICATION_TITLE, title);
  assert.equal(windows.env?.PI_NOTIFICATION_BODY, body);
});

test("notification bodies are bounded", () => {
  const invocation = notificationInvocation("linux", "Pi", "x".repeat(1_000))!;
  assert.equal(invocation.args.at(-1)?.length, 500);
});
