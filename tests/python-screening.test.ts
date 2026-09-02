import test from "node:test";
import assert from "node:assert/strict";
import { pythonOperations } from "../python-screening.ts";

test("ordinary Python command-shaped fixtures remain data", () => {
  assert.deepEqual(pythonOperations(`
fixture = "git push --force origin main"
assert "--force" in fixture
def open(path, mode):
    return (path, mode)
open("/tmp/not-a-write", "w")
`), { paths: [], executions: [] });
});

test("Python stdlib filesystem mutations expose concrete paths", () => {
  const result = pythonOperations(`
import os
import shutil as moves
from pathlib import Path as P
root = "/tmp/example"
file = P(root) / "output.txt"
file.write_text("value")
os.remove(root + "/old")
moves.copyfile("input", root + "/copy")
`);
  assert.deepEqual(result.paths, [
    { kind: "write", path: "/tmp/example/output.txt", source: "python:pathlib.write_text" },
    { kind: "delete", path: "/tmp/example/old", source: "python:os.remove" },
    { kind: "read", path: "input", source: "python:shutil.copyfile" },
    { kind: "write", path: "/tmp/example/copy", source: "python:shutil.copyfile" },
  ]);
});

test("Python subprocess calls distinguish argv, shell, and dynamic values", () => {
  const result = pythonOperations(`
import os
from subprocess import run
run(["git", "status", "--short"])
run("rm /tmp/example", shell=True)
os.system(runtime_command)
open(runtime_path, runtime_mode)
`);
  assert.deepEqual(result.executions, [
    { kind: "module", path: "os", source: "python static import", sourceRelative: true, language: "python" },
    { kind: "module", path: "subprocess", source: "python static import", sourceRelative: true, language: "python" },
    { kind: "argv", executable: "git", args: ["status", "--short"], source: "python:subprocess.run" },
    { kind: "shell", command: "rm /tmp/example", source: "python:subprocess.run" },
    { kind: "shell", command: undefined, source: "python:os.system" },
  ]);
  assert.deepEqual(result.paths, [
    { kind: "read", path: undefined, source: "python:open" },
    { kind: "write", source: "python:open with dynamic mode" },
  ]);
});

test("invalid Python fails closed as a parse error", () => {
  const result = pythonOperations("if True print('broken')\n");
  assert.equal(typeof result.parseError, "string");
  assert.deepEqual(result.paths, []);
  assert.deepEqual(result.executions, []);
});
