import test from "node:test";
import assert from "node:assert/strict";
import { informationalInvocation } from "../informational-commands.ts";

test("npm metadata and local inspection are informational", () => {
  for (const args of [
    ["view", "@lezer/python", "version", "--json"],
    ["ls", "@lezer/python", "--depth=0"],
    ["audit", "--omit=dev"],
    ["config", "get", "registry"],
    ["pkg", "get", "scripts.test"],
    ["--version"],
  ]) assert.equal(informationalInvocation("npm", args).handled, true, args.join(" "));

  for (const args of [
    ["audit", "fix"], ["audit", "--fix=true"], ["version", "patch"], ["config", "set", "registry", "x"],
    ["version", "--from-git"],
  ]) {
    assert.equal(informationalInvocation("npm", args).handled, false, args.join(" "));
  }
});

test("runtime and pip information are narrowly classified", () => {
  assert.equal(informationalInvocation("node", ["--version"]).handled, true);
  assert.deepEqual(informationalInvocation("node", ["--check", "script.js"]), { handled: true, readPaths: ["script.js"] });
  assert.equal(informationalInvocation("node", ["--import=./setup.js", "--check", "script.js"]).handled, false);
  assert.equal(informationalInvocation("python", ["--version"]).handled, true);
  assert.equal(informationalInvocation("python", ["-v"]).handled, false);
  assert.equal(informationalInvocation("python", ["-m", "pip", "list"]).handled, true);
  assert.equal(informationalInvocation("python", ["-m", "pip", "install", "package"]).handled, false);
  assert.equal(informationalInvocation("npx", ["--version"]).handled, true);
  assert.equal(informationalInvocation("go", ["version"]).handled, true);
});

test("package-manager configuration writes are not informational", () => {
  assert.equal(informationalInvocation("pnpm", ["list"]).handled, true);
  assert.equal(informationalInvocation("pnpm", ["config", "set", "key", "value"]).handled, false);
  assert.equal(informationalInvocation("yarn", ["config", "get", "key"]).handled, true);
  assert.equal(informationalInvocation("yarn", ["config", "set", "key", "value"]).handled, false);
});
