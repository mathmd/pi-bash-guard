import test from "node:test";
import assert from "node:assert/strict";
import { javascriptExecutions } from "../javascript-screening.ts";

test("ordinary JavaScript and TypeScript command fixtures remain data", () => {
  const result = javascriptExecutions(`
    const forcedPush = "git push --force origin main";
    const formatter = "mkfs /dev/example";
    analyzer.analyzeCommand(forcedPush);
    assert.equal(formatter.includes("mkfs"), true);
  `);
  assert.deepEqual(result, { executions: [] });
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
    executions: [
      { kind: "shell", command: "git push --force origin main" },
      { kind: "argv", executable: "dd", args: ["if=input", "of=/dev/example"] },
    ],
  });
});

test("CommonJS child-process namespaces and fork targets are recognized", () => {
  const result = javascriptExecutions(`
    const childProcess = require("child_process");
    childProcess.execFileSync("git", ["status", "--short"]);
    childProcess.fork("./worker.js");
  `);
  assert.deepEqual(result, {
    executions: [
      { kind: "argv", executable: "git", args: ["status", "--short"] },
      { kind: "module", path: "./worker.js" },
    ],
  });
});

test("invalid JavaScript fails closed as a parse error", () => {
  const result = javascriptExecutions("const broken = ;");
  assert.equal(result.executions.length, 0);
  assert.equal(typeof result.parseError, "string");
});
