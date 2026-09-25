import test from "node:test";
import assert from "node:assert/strict";
import { juliaOperations } from "../julia-screening.ts";

test("ordinary Julia command-shaped fixtures and shadowed Base names remain data", () => {
  assert.deepEqual(juliaOperations(`
fixture = "git push --force origin main"
function open(path, mode)
  (path, mode)
end
rm(path) = path
open("/tmp/not-a-write", "w")
rm("/tmp/not-a-delete")
`), { paths: [], executions: [] });
});

test("Julia Base and stdlib filesystem operations expose concrete paths", () => {
  const result = juliaOperations(`
root = "/tmp/example"
out = joinpath(root, "output.txt")
TOML.parsefile("config/verification.toml")
read("input.txt", String)
open(out, "w") do io
  write(io, "value")
end
open(joinpath(root, "dynamic-mode.txt"), runtime_mode)
cp("source", joinpath(root, "copy"))
mv(joinpath(root, "old"), joinpath(root, "new"))
rm(joinpath(root, "obsolete"))
include(joinpath(@__DIR__, "local.jl"))
`, { cwd: "/tmp/project", sourceDirectory: "/tmp/project/scripts", sourceFile: "/tmp/project/scripts/main.jl" });

  assert.deepEqual(result.paths, [
    { kind: "read", path: "config/verification.toml", source: "julia:TOML.parsefile" },
    { kind: "read", path: "input.txt", source: "julia:read" },
    { kind: "write", path: "/tmp/example/output.txt", source: "julia:open" },
    { kind: "write", path: undefined, source: "julia:write" },
    { kind: "read", path: "/tmp/example/dynamic-mode.txt", source: "julia:open" },
    { kind: "write", path: "/tmp/example/dynamic-mode.txt", source: "julia:open" },
    { kind: "read", path: "source", source: "julia:cp" },
    { kind: "write", path: "/tmp/example/copy", source: "julia:cp" },
    { kind: "delete", path: "/tmp/example/old", source: "julia:mv" },
    { kind: "write", path: "/tmp/example/new", source: "julia:mv" },
    { kind: "delete", path: "/tmp/example/obsolete", source: "julia:rm" },
  ]);
  assert.deepEqual(result.executions, [
    { kind: "module", path: "/tmp/project/scripts/local.jl", source: "julia:include", sourceRelative: true, language: "julia" },
  ]);
});

test("Julia command literals expose concrete and partially concrete argv", () => {
  const result = juliaOperations(`
ref = "artifact:current"
cmd = \`producer fetch $ref\`
read(cmd, String)
run(\`shell-tool -c "quoted payload"\`)
args = ["worker", "status", runtime_argument]
run(Cmd(args; dir=runtime_directory))
run(runtime_command)
run(pipeline(\`left-stage --emit\`, \`right-stage --consume\`))
`);
  assert.deepEqual(result.executions, [
    { kind: "argv", executable: "producer", args: ["fetch", "artifact:current"], source: "julia:read" },
    { kind: "argv", executable: "shell-tool", args: ["-c", "quoted payload"], source: "julia:run" },
    { kind: "argv", executable: "worker", args: ["status", undefined], source: "julia:run", dynamicCwd: true },
    { kind: "argv", executable: undefined, args: undefined, source: "julia:run" },
    { kind: "argv", executable: "left-stage", args: ["--emit"], source: "julia:run" },
    { kind: "argv", executable: "right-stage", args: ["--consume"], source: "julia:run" },
  ]);
});

test("Julia verification-style source distinguishes concrete and runtime paths", () => {
  const result = juliaOperations(`
using SHA, TOML
rec = TOML.parsefile("scripts/threshold_flux/output/verification.toml")
old = read(\`git show HEAD:main.tex\`, String)
new = read("main.tex", String)
for line in eachline("/tmp/necklacetex-before.test")
  hash, path = split(line; limit=2)
  open(sha256, path)
end
`);
  assert.deepEqual(result.paths, [
    { kind: "read", path: "scripts/threshold_flux/output/verification.toml", source: "julia:TOML.parsefile" },
    { kind: "read", path: "main.tex", source: "julia:read" },
    { kind: "read", path: "/tmp/necklacetex-before.test", source: "julia:eachline" },
    { kind: "read", path: undefined, source: "julia:open" },
  ]);
  assert.deepEqual(result.executions, [
    { kind: "argv", executable: "git", args: ["show", "HEAD:main.tex"], source: "julia:read" },
  ]);
});

test("reported Julia verification body parses as source rather than a shell path", () => {
  const source = [
    'using SHA,TOML;',
    'rec=TOML.parsefile("scripts/threshold_flux/output/verification.toml"); for group in ("source_sha256","output_sha256"), (path,hash) in rec[group]; @assert bytes2hex(open(sha256,path))==hash path; end;',
    'old=read(`git show 9d140ec308413b494ea9f7f6980b1b6ddfc933d2:main.tex`,String); new=read("main.tex",String);',
    String.raw`stripfigure(s)=replace(s,r"\\begin\{figure\}\[htbp\](?:(?!\\end\{figure\}).)*?\\label\{het_tang\}.*?\\end\{figure\}"s=>"TARGET_FIGURE");`,
    '@assert stripfigure(old)==stripfigure(new); n=0; for line in eachline("fixture/necklacetex-before"); hash,path=split(line;limit=2); path=="main.tex" && continue; @assert bytes2hex(open(sha256,path))==hash path; global n+=1; end;',
    'println("Verified ",n," existing-file hashes.")',
  ].join(" ");
  const result = juliaOperations(source);
  assert.equal(result.parseError, undefined);
  assert.ok(result.paths.some((operation) => operation.path === "scripts/threshold_flux/output/verification.toml"));
  assert.ok(result.paths.some((operation) => operation.path === "main.tex"));
  assert.ok(result.executions.some((execution) => execution.kind === "argv" && execution.executable === "git"));
});

test("invalid Julia fails closed as a parse error", () => {
  const result = juliaOperations("function broken(\n");
  assert.equal(typeof result.parseError, "string");
  assert.deepEqual(result.paths, []);
  assert.deepEqual(result.executions, []);
});

test("Julia source operation discovery is bounded", () => {
  const result = juliaOperations(Array.from({ length: 1_026 }, () => 'read("value")').join(";"));
  assert.match(result.parseError ?? "", /more than 1024 bounded operations/);
  assert.deepEqual(result.paths, []);
  assert.deepEqual(result.executions, []);
});
