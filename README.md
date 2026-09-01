# bash-guard

A local Pi extension that combines shell hazard detection with explicit path ownership.

## Decisions

- Unowned paths are readable unless secret; modifying or executing them asks once.
- Pi-created paths receive edit ownership until the agent becomes idle.
- Pi-created paths under `/tmp` retain edit ownership for the Pi session.
- Git-tracked regular files automatically receive edit ownership when the working directory is the repository root, any nested subdirectory, or a symlink resolving into either; tracked files currently deleted from the worktree are included.
- Edit ownership permits modification/deletion, execute ownership permits execution without editing, and full ownership combines both capabilities.
- Secret reads, catastrophic commands, direct `.git` writes, and irreversible unowned deletion are denied.
- Remote mutations and mutative Git/systemd commands always ask; filesystem searches, systemd inspection, HTTP GET/HEAD requests, common network diagnostics, and read-only IPP attribute queries do not.
- Wrappers such as `timeout` inherit the classification of the command they run.
- Shell `command -v`/`command -V` inspection is non-executing and does not treat the queried name as a command; other `command` forms still inherit the wrapped command’s classification.
- Shell interpreter `-c` source is analyzed recursively as shell; inline JavaScript, Python, Ruby, Perl, Deno, and Bun source is treated as opaque code requiring approval rather than misparsed as shell.
- Persistent shell assignments are resolved across compound commands; copy operations check concrete destination files rather than requiring ownership of the destination directory.
- Command-position variables from literal assignments and literal `for … in …` lists are resolved statically and prompted per executable candidate; dynamic values remain unresolved and are labeled explicitly.
- Path inference recognizes whole path arguments, not slash-containing code snippets, command strings, URLs, or other embedded text.
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

This is static policy enforcement, not a sandbox. Full ownership of a script means its opaque side effects are trusted. Generic tools are guarded only when their public input contains recognizable path fields. Automatic ownership is recorded only for successful creations that can be attributed conservatively.
