# bash-guard

A local Pi extension that combines shell hazard detection with explicit path ownership.

## Decisions

- Existing unowned paths are readable unless secret; modifying or executing them asks once. Known-missing literal paths do not require ownership, while protected policy, secret, `.git`, and system locations retain their safety rules.
- Pi-created paths receive edit ownership until the agent becomes idle.
- Pi-created paths under `/tmp` retain edit ownership for the Pi session. Runtime names containing `$$` are discovered after successful creation so later cleanup can use that same ownership.
- Git-tracked regular files automatically receive edit ownership when the working directory is the repository root, any nested subdirectory, or a symlink resolving into either; tracked files currently deleted from the worktree are included.
- Edit ownership permits modification/deletion, execute ownership permits execution without editing, and full ownership combines both capabilities.
- Secret reads, catastrophic commands, direct `.git` writes, and irreversible unowned deletion are denied. Shell catastrophe matching follows executable command positions and known nested execution contexts instead of treating every quoted command-shaped string as executable.
- Remote mutations and mutative Git/systemd commands always ask. A clone into a new `/tmp` destination is treated as remote read plus attributable local creation; filesystem searches, systemd inspection, documented Nix inspections, Hyprland information commands, HTTP GET/HEAD requests, common network diagnostics, and read-only IPP attribute queries also do not ask.
- Wrappers such as `timeout` inherit the classification of the command they run.
- Shell `command -v`/`command -V` inspection is non-executing and does not treat the queried name as a command; other `command` forms still inherit the wrapped command’s classification.
- `trap` inspection/reset forms are safe, while a deferred trap action is recursively analyzed as shell. Common state-only builtins such as `let`, `getopts`, `caller`, and `times`, `builtin` wrappers, and `[[ … ]]` tests are recognized.
- Shell interpreter `-c` source is analyzed recursively. JavaScript/TypeScript and Python file, `-e`/`-c`, and direct heredoc source is parsed without execution; inline source itself needs no ownership, but detected side effects retain ordinary policy checks. Ruby, Perl, Lua/LuaJIT, Deno, and Bun inline source remains opaque and asks. `luac -p` remains read-only syntax checking.
- Shell, JavaScript/TypeScript, and Python executable source propagates concrete mutation and execution targets back to the outer command. Local module imports require execute ownership; Node `node:fs` and Python `os`, `shutil`, `pathlib`, and `open` mutations require edit ownership; child processes receive normal command and path analysis. Recognized reads retain secret checks without adding ownership requirements. New concrete outputs become attributable creations. Dynamic mutation or execution targets ask and therefore block headlessly.
- Heredoc bodies are attached to the command consuming them instead of being parsed as independent shell commands. Quoted Node, Python, and shell heredocs receive language-aware screening; command substitutions in unquoted data are still analyzed, and unresolved unquoted expansion asks.
- `node --test` resolves explicit files, quoted test globs, directories, or Node's default test discovery under the effective working directory. JavaScript/TypeScript is parsed without execution: ordinary command-shaped fixture strings remain data, while concrete commands passed to known `node:child_process` sinks receive normal catastrophic screening. Selected sources still require execute ownership. Discovery is capped at 512 files and source inspection at 256 KiB; over-limit or unparsable input asks.
- `npm test` and `npm run <script>` resolve the nearest static `package.json` and analyze pre/main/post lifecycle commands in order. Forwarded arguments remain data, while workspaces, custom script shells, recursion, malformed manifests, and unresolved selection ask.
- Curated informational invocations are non-mutative: npm metadata/list/audit-without-fix queries, runtime version/help checks, Node syntax checks, pip inspection, and narrow pnpm/yarn/tool version queries are allowed. Mutative lookalikes such as `npm audit fix`, `npm version patch`, config writes, installs, arbitrary Python modules, and unknown binaries remain guarded.
- Command substitutions (`$(…)` and backticks) are analyzed recursively, while their resulting text is treated as data in the surrounding command rather than as additional shell syntax.
- Persistent shell assignments are propagated across compound commands. Literal values remain concrete; `mktemp` output and path values containing `$$` receive stable symbolic descriptions instead of being mislabeled unresolved. Copy operations check concrete destination files rather than only destination directories.
- Variables from literal assignments and literal `for … in …` lists are resolved statically, including path-position loop variables. Other dynamic values remain unresolved and are labeled explicitly.
- Unquoted shell globs are expanded against the working directory before path policy checks. Permission details list each concrete match; unresolved or over-limit expansions fail closed instead of creating wildcard-shaped ownership entries.
- Path inference recognizes whole path arguments, not slash-containing code snippets, quoted source text, command strings, URLs, or other embedded text.
- Headless sessions block anything that would ask.
- Reads and execution under `/nix/store` bypass ownership prompts; attempted mutation is denied.
- Standard process I/O endpoints such as `/dev/null`, standard streams, and file descriptors 0–2 bypass ownership checks when used for I/O.
- Desktop notifications announce permission prompts and when the agent becomes idle.

## Policies

Global policy: `~/.pi/agent/extensions/bash-guard/policy.json`

Project policy: `<project>/.pi/bash-guard.json` (loaded only for trusted projects)

```json
{
  "version": 3,
  "ownership": {
    "edit": ["./generated/**", "!./generated/protected/**"],
    "execute": ["./scripts/**", "!./scripts/untrusted/**"],
    "full": ["/absolute/trusted/tools/**"]
  },
  "secrets": ["./private/**"],
  "commands": {
    "include": [
      ["project-inspect", "--json", "**"],
      ["release-*", "--dry-run"]
    ],
    "exclude": [
      ["project-inspect", "--write", "**"]
    ]
  },
  "tools": {
    "read": ["anchor_grep"]
  },
  "permissionTimeout": "1m30s"
}
```

Ownership lists use ordered Gitignore-style patterns. The last matching positive or `!` negative controls membership in each capability. Full is checked first; matching both edit and execute is also treated as full. Otherwise paths fall back to read-only. Global lists are evaluated before trusted local lists.

Command entries are unordered string lists. The first member is a glob for the command name; remaining members are argument globs matched one-to-one without regard to order. Without a final `**`, the argument multiset must match exactly. Final `**` permits unmatched arguments. Exclusions override inclusions by removing trust; they do not create deny rules. Backslash escapes literal `*`, `?`, or `\`. Matching entries suppress only the otherwise-unknown command decision: path-like arguments are still interpreted and enforced through secret, `.git`, and ownership rules, while built-in safety classifications and catastrophic screening retain precedence.

Run `/bash-guard`, choose global or local, and the policy opens directly in `$VISUAL`, `$EDITOR`, or `nano`. Version 3 is required and older policies are not migrated automatically. Exact tool names in `tools.read` make recognizable path inputs read-only while retaining secret checks. `permissionTimeout` accepts `0`, `"45s"`, `"2m"`, or combined durations such as `"1m30s"`; trusted local settings override global settings.

## Approval choices

A flagged operation offers one-time approval or refusal with an optional follow-up comment. Mutation prompts offer edit/full grants, execution prompts offer execute/full grants, and ambiguous path access offers edit/execute/full. Persistent choices append the exact path and open the policy at that entry. Unknown commands similarly offer an exact argument-aware trust entry, and unknown tools can be added to `tools.read`; both flows open the editor at the inserted line. Neovim receives `+<line>`. Literal standalone unowned deletion may be replaced with `gio trash`.

Menus use `j`/`k` or arrow keys to move, `l` or Enter to accept, and `h` to go back one level. Long command/reason details keep the options visible; use Ctrl-U/Ctrl-D or `g`/`G` to inspect every detail page. Esc and Ctrl-C cancel the entire flow. A nonzero permission timeout automatically refuses each unanswered permission prompt when its timer expires.

## Limits

This is static policy enforcement, not a sandbox. Parsed source inspection recognizes bounded literal values and selected built-in Node/Python APIs; it does not prove dynamic dispatch, arbitrary data flow, native extensions, reflection, or imported third-party dependency behavior safe. Recognized unresolved mutation, secret-read, module, or process targets ask, while side effects through unrecognized APIs remain covered only by ownership of the enclosing executable source. Generic tools are guarded only when their public input contains recognizable path fields. Automatic ownership is recorded only for successful creations that can be attributed conservatively.
