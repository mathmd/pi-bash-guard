# bash-guard

A Pi extension that combines shell hazard detection with explicit path ownership, approval dialogs, and static source inspection.

**This is an approval guard, not a sandbox.** Run untrusted code in an OS-level sandbox; see [Limits](#limits).

## Installation

Install [Pi](https://github.com/earendil-works/pi) first, then:

```sh
pi install git:github.com/mathmd/pi-bash-guard
```

Restart Pi or run `/reload`. Run `/bash-guard` to open this machine's global or project policy. New installations start without additional ownership or command-trust grants; YOLO remains off.

Requirements: Node.js **22.19.0 or newer**, npm, Git, Bash, and a compatible Pi host (tested with **Pi 1.1.0** on Linux). Pi installs the production dependencies; its own APIs are supplied by the host, not bundled with this extension. Native Tree-sitter parsers use packaged prebuilds where available; other platforms may need Python, make, and a C/C++ compiler for node-gyp. Julia itself is not required for source inspection. Other operating systems have not been validated.

`gio` (GLib) is needed for **Move to trash instead** and the test fixtures. Desktop notifications are best-effort (`notify-send` on Linux); their absence does not disable enforcement. Set `VISUAL` or `EDITOR` for policy editing.

To update or remove the managed package:

```sh
pi update git:github.com/mathmd/pi-bash-guard
pi remove git:github.com/mathmd/pi-bash-guard
```

Reload after updating or removing it. Removal leaves your policy in user state. Install only one copy: do not keep an auto-discovered extension checkout and a managed package active at the same time. A development checkout already loaded by Pi needs no second installation. No npm publication/account is needed; `private: true` prevents accidental npm publication while allowing Git installation.

## Development

```sh
git clone https://github.com/mathmd/pi-bash-guard.git
cd pi-bash-guard
npm ci
npm run check
```

`npm run check` runs strict TypeScript checking and the test suite. Tooling and the test Pi host are development dependencies resolved locally; no Nix-store or global-installation paths are required. The lockfile pins the test environment. CI runs on Linux with Node 22 and 24.

For manual testing, load the checkout with `pi -e ./index.ts` from a workspace that has no other bash-guard installation active. Set `PI_CODING_AGENT_DIR` to a separate scratch directory if you want isolated settings and policy. Do not commit live policy, credentials, dependency directories, or operational scratch files. Keep machine-specific permissions private.

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
- Shell interpreter `-c` source is analyzed recursively. JavaScript/TypeScript, Python, and Julia file, inline (`-e`/`-c`/`--eval`), preload, and direct heredoc source is parsed without executing the runtime or source; recognized inline source arguments are excluded from outer-shell path inference. Inline source itself needs no ownership, but detected side effects retain ordinary policy checks. Ruby, Perl, Lua/LuaJIT, Deno, and Bun inline source remains opaque and asks. `luac -p` remains read-only syntax checking.
- Shell, JavaScript/TypeScript, Python, and Julia source screening is evidence-based: a recognized operation affects permission only when its relevant path, command, executable, or module target is statically concrete. Concrete local imports/includes require execute ownership; Node `node:fs`, Python `os`/`shutil`/`pathlib`/`open`, and selected Julia Base/stdlib filesystem mutations require edit ownership; recognized reads retain secret checks. Fully concrete child-process or Julia command-literal executions receive normal analysis. Partially concrete argv calls retain concrete path checks and hard denials, but ordinary approvals caused by unresolved arguments are omitted. New concrete outputs become attributable creations; all other unresolved source-internal effects rely on the enclosing script's execution approval.
- Source-content recursion follows canonical project-local imports and Julia `include`/`-L` entries, including imports reached after a static `cd`. Installed dependencies, `/nix/store`, `node_modules`, Julia depot package/artifact/compiled trees, runtime libraries, and imports escaping the project through symlinks are content-inspection boundaries; their concrete paths still receive ordinary execute/path checks. Explicit non-dependency script entries outside the project are still screened.
- Heredoc bodies are attached to the command consuming them instead of being parsed as independent shell commands. Quoted Node, Python, Julia, and shell heredocs receive language-aware screening; command substitutions in unquoted data are still analyzed, and unresolved unquoted expansion asks.
- `node --test` resolves explicit files, quoted test globs, directories, or Node's default test discovery under the effective working directory. JavaScript/TypeScript is parsed without execution: ordinary command-shaped fixture strings remain data, while concrete commands passed to known `node:child_process` sinks receive normal catastrophic screening. Selected sources still require execute ownership. Discovery is capped at 512 files and inspected project-local source at 256 KiB; over-limit or unparsable local input asks.
- `npm test` and `npm run <script>` resolve the nearest static `package.json` and analyze pre/main/post lifecycle commands in order. Forwarded arguments remain data. Workspaces, custom script shells, recursion, malformed manifests, and unresolved direct selection ask; dynamic selection encountered only inside approved source adds no separate prompt.
- Curated informational invocations are non-mutative: npm metadata/list/audit-without-fix queries, runtime version/help checks, Node syntax checks, pip inspection, and narrow pnpm/yarn/tool version queries are allowed. Mutative lookalikes such as `npm audit fix`, `npm version patch`, config writes, installs, arbitrary Python modules, and unknown binaries remain guarded.
- Command substitutions (`$(…)` and backticks) are analyzed recursively, while their resulting text is treated as data in the surrounding command rather than as additional shell syntax.
- Persistent shell assignments are propagated across compound commands. Literal values remain concrete; `mktemp` output and path values containing `$$` receive stable symbolic descriptions instead of being mislabeled unresolved. Copy operations check concrete destination files rather than only destination directories.
- Variables from literal assignments and literal `for … in …` lists are resolved statically, including path-position loop variables. Dynamic values in direct shell/tool input remain unresolved and fail closed where authority is needed; unresolved values discovered only inside approved source are treated as absence of concrete evidence.
- Unquoted shell globs are expanded against the working directory before path policy checks. Permission details list each concrete match; direct unresolved or over-limit expansions fail closed instead of creating wildcard-shaped ownership entries. Local-source over-limit safeguards also remain fail-closed.
- Path inference recognizes whole path arguments, not slash-containing code snippets, quoted source text, command strings, URLs, or other embedded text.
- Headless sessions block anything that would ask, unless explicitly opted into session-local YOLO approvals. YOLO auto-allows only `ask`; every `deny` still blocks without prompting.
- Reads and execution under `/nix/store` bypass ownership prompts; attempted mutation is denied.
- Standard process I/O endpoints such as `/dev/null`, standard streams, and file descriptors 0–2 bypass ownership checks when used for I/O.
- Desktop notifications announce permission prompts and when the agent becomes idle.

## Shell context and inherited paths

Each Bash call starts with a fresh context. The analyzer tracks generic scalar assignments, aliases, supported declarations, append assignments, known-unset versus empty values, and simple non-mutating defaults such as `${root:-$HOME}`. `$PWD` and known `$OLDPWD` follow directory state; logical `cd` and physical `cd -P` are distinct. Saved aliases do not change when the directory changes. Subshells and command substitutions inherit facts without leaking assignments back into the parent.

For example, these paths can be resolved without running the commands during analysis:

```sh
root="$PWD"
cache="${XDG_CACHE_HOME:-$HOME/.cache}"
cd child
cat "$root/config.json" "$PWD/value.txt" "$cache/report.json"
```

Inherited lookup is deliberately restricted to reviewed, bounded, absolute single-path values (or explicit empty/unset values): `HOME`, `OLDPWD`, `TMPDIR`, `TMP`, `TEMP`, `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME`, `XDG_RUNTIME_DIR`, `PI_CODING_AGENT_DIR`, and `PI_CODING_AGENT_SESSION_DIR`. Relevant references and implicit dependencies are captured once per call. Initial `PWD` must agree with the effective tool cwd; arbitrary parent `PWD` is not trusted. No XDG defaults are invented. Arbitrary inherited names such as `API_TOKEN`, and path lists such as `PATH`, are not imported or displayed. Rejected inherited values are not copied into diagnostics.

Unknown writes, unsupported variable attributes, unsafe unquoted splitting/globbing, and uncertain directory changes invalidate facts rather than reuse stale values. Conditional alternatives retain concrete evidence, including through aliases. Pipeline/background scope is isolated conservatively, including Bash's optional `lastpipe` behavior. Analysis is bounded to 128 candidate combinations, 1,024 inspected command units, and 32 nested shell inspections. Runtime/random parameters and arbitrary substitution output remain unknown; existing symbolic `mktemp`/PID handling is unchanged in principle. No source or inherited value is executed or evaluated to discover a binding.

### Execution-time verification

Pi's permission hook runs before the eventual command prefix/spawn hook and cannot directly read that final environment. An approved Bash call therefore receives a short verification prefix, executed in the **actual tool shell** after that setup. It checks cwd, captured values, their ordinary scalar attributes, and splitting/search-path assumptions where applicable, without assigning or exporting replacement values. A mismatch prints a generic diagnostic and exits **125 before the submitted body runs**, even under YOLO. Reconcile the startup/prefix/spawn configuration before retrying; merely using literal operands does not remove the cwd/HOME checks.

This retains Pi's execution backend and any external sandbox. It is not a sandbox, a proof about arbitrary startup code, or protection against side effects in setup that runs before the checks. Like any inserted shell prefix, verification can affect ephemeral shell metadata such as line numbers and the previous-command status. Binding facts are not carried into later tool calls or imported into JavaScript/Python/Julia source evaluation.

Resolving a variable does **not** authorize its target or its command. Secret, ownership, `.git`, catastrophic, and system-path checks still apply. In particular, `nix flake metadata --no-write-lock-file "path:$PWD/project"` loses the unresolved-path reason, but still requires managed-state approval; secret-file reads remain denied.

## Policies

Global policy: `~/.pi/agent/bash-guard/policy.json`, or `$PI_CODING_AGENT_DIR/bash-guard/policy.json` when Pi's agent directory is overridden. This location is independent of the checkout or package-installation directory.

Project policy: `<project>/.pi/bash-guard.json` (loaded only for trusted projects)

On first use, if the new global policy does not exist, the guard preserves a valid version-3 policy from `<agent-dir>/extensions/bash-guard/policy.json` by copying its exact contents. The old file remains as a backup; subsequent edits use the new location. An existing destination is never overwritten. Invalid/older legacy policies or failures while preserving them stop tool calls, including YOLO calls, until the configuration is repaired. This changes storage location, not policy schema.

Policy files beside arbitrary package checkouts are **not** imported. When moving from a nonstandard installation, copy your reviewed private policy to the new global location yourself. Configure each machine separately, or review absolute paths before copying permissions; do not publish your live policy. `policy.example.json` is a reference, not a file loaded automatically.

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

A flagged operation offers one-time approval, refusal with an optional multiline comment, and **Steer or ask…**. Mutation prompts offer edit/full grants, execution prompts offer execute/full grants, and ambiguous path access offers edit/execute/full. Persistent choices append the exact path and open the policy at that entry. Unknown commands similarly offer an exact argument-aware trust entry, and unknown tools can be added to `tools.read`; both flows open the editor at the inserted line. Neovim receives `+<line>`. Literal standalone unowned deletion may be replaced with `gio trash`.

**Steer or ask… defers the operation so the main agent can respond before you decide.** Submitting a nonempty message closes the permission dialog, blocks that tool call without executing or rewriting it, and sends your text through Pi's native steering queue. The next model turn receives both your message and the original permission context/reasons. There is no second permission selection before that response. This grants no permission or ownership and is not treated as a user refusal; policy hard denials remain in force.

While the discussion is open, a **bash-guard: discussing · reply to continue** status is shown. Remaining tool preflights and later tool requests are held without more permission menus, even if YOLO is enabled. If the model tries tools instead of answering, those requests stop rather than repeatedly reopening approvals. Reply in chat to resume normal checks; any retried operation is analyzed afresh and may ask again. Blank/cancelled steering returns to the original menu. Idle, compaction, and extension-injected messages do not release the pause; a new interactive/RPC user message or session replacement/reload does.

Pi delivers steering at a tool-batch boundary. Already admitted or running sibling calls may finish; this is not a rollback or cancellation of earlier approvals. The guard does not change the active-tool set, replace the execution backend, or use a separate model to answer.

Menus use `j`/`k` or arrow keys to move, `l` or Enter to accept, and `h` to go back one level. Long command/reason details keep the options visible; use Ctrl-U/Ctrl-D or `g`/`G` to inspect every detail page. Steering and refusal comments use Pi's multiline editor: Enter submits, Shift-Enter/Ctrl-J inserts a newline, and the configured `app.editor.external` binding (Ctrl-G by default) opens the draft in the configured external editor. Esc returns from steering or cancels an optional comment; Esc/Ctrl-C at a permission menu cancels the entire flow. A nonzero permission timeout automatically refuses each unanswered permission menu; opening a text editor pauses that menu instance and returning starts a fresh prompt timeout.

## YOLO approvals for externally sandboxed runs

YOLO is **off by default**. It automates bash-guard's one-time permission decisions across Bash and other guarded tools; it does not disable analysis or create a sandbox.

- `/bash-guard-yolo on` enables it for the current session.
- `/bash-guard-yolo off` restores normal permission prompting (or fail-closed behavior headlessly).
- `/bash-guard-yolo status` reports the current mode; bare `/bash-guard-yolo` toggles it.
- While enabled, a warning-colored **⚠ bash-guard YOLO** marker stays in Pi's footer/status area.

For an unattended launch inside your sandbox, explicitly opt in at startup:

```sh
pi --bash-guard-yolo -p "Complete the task and run its tests"
```

Every tool call is still fully analyzed. `ask` receives a one-time allowance without a permission menu, timeout, or attention notification. **All existing hard denials remain**: catastrophes, secret access, unowned permanent deletion, direct `.git` mutations, and system read-only mutations. A denial in any part of a compound call blocks the entire call immediately, even interactively; YOLO never automatically rewrites deletion into trash.

YOLO writes no ownership grants, command/tool trust entries, policy settings, or saved mode state. Normal successful-creation ownership tracking still applies. The mode survives idle and compaction, but resets on `/reload`, `/new`, `/resume`, `/fork`/`/clone`, shutdown, and restart. The CLI flag applies only to the initial startup session, not subsequent resets. Independent headless Pi launches still need explicit opt-in. Supported native background subagents can instead follow their parent's live mode, as described below.

Use external isolation (for example jail.nix) yourself. YOLO neither detects nor verifies a sandbox, cannot bypass other extensions' restrictions, and does not suppress unrelated Pi dialogs or agent questions. Auto-approving unresolved targets and arbitrary execution carries the same risks as manually choosing **Allow once**.

### Live inheritance for native background subagents

With official **pi-subagents 0.77.0**, bash-guard supplies launch metadata for new native background children requested through the `subagent` tool. No fork or replacement pi-subagents package is required. Both parent and child must load bash-guard, the parent must have a session file, and both processes must share the same local runtime directory. Use `async: true`; the upstream default is also background execution. Installing this version does not retrofit already-running children using older code.

An inheriting child checks its live parent **at each tool permission decision**, without caching a positive mode. Starting with the parent off does not permanently disable inheritance: later on/off/on toggles affect the same running child. Nested background children follow their immediate parent's effective mode. A strict or opted-out child cannot pass inherited YOLO to descendants. Commands already approved or running are not cancelled, and stopped children are not restarted.

To opt a new tool launch out, the parent agent can use:

```json
{"agent":"worker","task":"Review the change","async":true,"options":{"bashGuardInheritYolo":false}}
```

Bash-guard consumes that option before handing the call to pi-subagents. For an individual child inside a scripted workflow, use its existing binding option:

```json
{
  "agent": "worker", "task": "Review the change", "async": true,
  "extensionBindings": { "pi-bash-guard/1": { "inheritYolo": false } }
}
```

The launch metadata identifies a parent; it does not authorize YOLO. The child checks its actual SDK session-header parent against that metadata, then queries the parent's private local socket. Other binding namespaces are preserved when the guard prepares a tool call. In pi-subagents 0.77.0, a scripted child's own `extensionBindings` replaces the whole workflow-default map; dropping the guard's route leaves that child strict. Do not manufacture parent metadata or copy it from another session.

**Boundaries and failure behavior:**

- Parent off, missing/malformed metadata, unreachable parent, invalid private runtime storage, or a query timeout means no inherited auto-approval. Phase one does **not** forward permission prompts: headless asks still refuse when YOLO is off.
- Foreground in-process, extension-isolated, external/non-Pi, and alternate delegation APIs are not covered. Ambient runner metadata must not enable an unrelated foreground session. For external runners or mixed workflows, use `options.bashGuardInheritYolo:false` to avoid injecting unsupported binding defaults. A child that does not load bash-guard is not guarded by this extension.
- Retained children keep their original inheritance route, not a saved mode. Their original parent's live state still governs while its authority is available. Route/opt-out changes on resume are rejected: start a fresh child to change the route. Parent shutdown/reload closes its authority; children fall back to strict mode. A new authority for the same session file can reconnect them; reloading a child itself resets its mode.
- The channel uses private per-user storage under `$TMPDIR/pi-bash-guard-<uid>` (normally `/tmp/pi-bash-guard-<uid>`), directory mode `0700`, records/sockets `0600`, and random authentication tokens. Records contain no saved YOLO boolean. Direct tool access to this control state is a hard denial. Normal shutdown removes owned records and sockets; crashes can leave inert remnants, which do not authorize anything without a live server.
- Requests are bounded to 4 KiB, eight parent hops, 32 simultaneous connections per authority, and a one-second timeout. Unix socket paths must fit within 100 bytes; a long `TMPDIR` needs shortening. This local same-user channel is not an OS sandbox or protection against hostile host processes/extensions.

## Tests

Run `npm test`. Tests use isolated `/tmp/bash-guard-*` fixtures and never execute the hazardous command strings being analyzed. Extension-hook tests load copied extensions with the development Pi dependency's real loader with isolated `PI_CODING_AGENT_DIR` values, without using the live policy. Steering regressions also run Pi's real agent loop in sequential and parallel modes with scripted model responses and harmless tool spies; they verify delivery before another approval, skipped calls, fresh retry checks, and retry-loop prevention without network/model calls. Shell-context tests execute only harmless verification probes. New YOLO, shell-context, and steering fixtures are cleaned with `gio trash`.

Policy-location regressions cover exact legacy preservation, destination precedence, symlinks, rejected invalid/older policies, filesystem failures, checkout-independent configuration, and fail-closed initialization under YOLO. Their scratch fixtures are also trashed.

Live-inheritance regressions cover repeated toggles, concurrent parents, nested opt-outs, malformed/mismatched metadata, unavailable authorities, lifecycle resets, retained-route restrictions, and private-control-state denials. A separate-process integration uses official pi-subagents 0.77.0's native launch builder and child-session factory with Pi's real loader, scripted offline provider responses, and actual harmless fixture tool operations. It verifies off/on/off/on changes in an already-running child, opt-out, wrong-parent rejection, secret denials, and parent shutdown. It does not contact a remote provider or claim end-to-end coverage of every workflow dispatcher. A real headless CLI test also runs a scripted harmless write with and without `--bash-guard-yolo`. pi-subagents is a development-only test dependency; consumers keep their ordinary official installation. Fixture cleanup uses `gio trash`.

## Limits

This is static policy enforcement, not a sandbox. Parsed source inspection recognizes bounded literal/static values and selected built-in Node, Python, and Julia APIs; it does not prove dynamic dispatch, arbitrary data flow, Julia package loading, native extensions, reflection, or dependency behavior safe. Julia package resolution is not executed: project-local `include` and explicit preload files are followed, while package/depot code is a trust boundary. Unresolved effects inside approved source do not independently prompt and can therefore access paths that static analysis cannot identify—the enclosing source's execution approval is the trust boundary. Installed and non-project dependency contents are not recursively inspected. Concrete path/command evidence still receives all secret, `.git`, catastrophic, and ownership checks. Generic tools are guarded only when their public input contains recognizable path fields, and automatic ownership is recorded only for successful creations that can be attributed conservatively.
