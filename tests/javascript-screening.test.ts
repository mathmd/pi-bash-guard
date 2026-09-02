import test from "node:test";
import assert from "node:assert/strict";
import { javascriptExecutions } from "../javascript-screening.ts";

test("ordinary JavaScript and TypeScript command fixtures remain data", () => {
  const result = javascriptExecutions(`
    import type { Fixture } from "./fixture-types.ts";
    const forcedPush = "git push --force origin main";
    const formatter = "mkfs /dev/example";
    const require = (value: string) => ({ value });
    require("./fixture-only.js");
    analyzer.analyzeCommand(forcedPush);
    assert.equal(formatter.includes("mkfs"), true);
  `);
  assert.deepEqual(result, { paths: [], executions: [] });
});

test("child-process shell and argv sinks expose concrete commands", () => {
  const result = javascriptExecutions(`
    import { execSync as runShell, spawnSync } from "node:child_process";
    const operation = "git push " + "--force origin main";
    const executable: string = "dd";
    const args = ["if=input", "of=/dev/example"];
    runShell(operation);
    spawnSync(executable, args);
  `);
  assert.deepEqual(result, {
    paths: [],
    executions: [
      { kind: "shell", command: "git push --force origin main", source: "node:child_process.execSync" },
      { kind: "argv", executable: "dd", args: ["if=input", "of=/dev/example"], source: "node:child_process.spawnSync" },
    ],
  });
});

test("CommonJS child-process namespaces and local module targets are recognized", () => {
  const result = javascriptExecutions(`
    const childProcess = require("child_process");
    childProcess.execFileSync("git", ["status", "--short"]);
    childProcess.fork("./worker.js");
    require("./helper.js");
  `);
  assert.deepEqual(result, {
    paths: [],
    executions: [
      { kind: "argv", executable: "git", args: ["status", "--short"], source: "node:child_process.execFileSync" },
      { kind: "module", path: "./worker.js", source: "node:child_process.fork", language: "javascript" },
      { kind: "module", path: "./helper.js", source: "CommonJS require", sourceRelative: true, language: "javascript" },
    ],
  });
});

test("Node filesystem mutations and dynamic process values are exposed", () => {
  const result = javascriptExecutions(`
    import * as fs from "node:fs";
    import { writeFile } from "node:fs/promises";
    import { spawn } from "node:child_process";
    const output = "/tmp/output.txt";
    fs.readFileSync("/tmp/input.txt");
    fs.writeFileSync(output, "value");
    writeFile("/tmp/async.txt", "value");
    fs.renameSync("/tmp/old", "/tmp/new");
    fs.rmSync(runtimePath);
    spawn("rm", [runtimePath]);
  `);
  assert.deepEqual(result.paths, [
    { kind: "read", path: "/tmp/input.txt", source: "node:fs.readFileSync" },
    { kind: "write", path: "/tmp/output.txt", source: "node:fs.writeFileSync" },
    { kind: "write", path: "/tmp/async.txt", source: "node:fs.writeFile" },
    { kind: "delete", path: "/tmp/old", source: "node:fs.renameSync" },
    { kind: "write", path: "/tmp/new", source: "node:fs.renameSync" },
    { kind: "delete", path: undefined, source: "node:fs.rmSync" },
  ]);
  assert.deepEqual(result.executions, [
    { kind: "argv", executable: "rm", args: [undefined], source: "node:child_process.spawn" },
  ]);
});

test("invalid JavaScript fails closed as a parse error", () => {
  const result = javascriptExecutions("const broken = ;");
  assert.equal(result.executions.length, 0);
  assert.equal(result.paths.length, 0);
  assert.equal(typeof result.parseError, "string");
});
