# bash-guard

A local Pi extension that combines shell hazard detection with explicit path ownership.

## Decisions

- Unowned paths are readable unless secret; modifying or executing them asks once.
- Pi-created paths receive edit ownership until the agent becomes idle.
- Pi-created paths under `/tmp` retain edit ownership for the Pi session.
- Edit ownership permits modification/deletion; full ownership additionally permits execution.
- Secret reads, catastrophic commands, direct `.git` writes, and irreversible unowned deletion are denied.
- Remote mutations and mutative Git commands always ask.
- Headless sessions block anything that would ask.
- Reads and execution under `/nix/store` bypass ownership prompts; attempted mutation is denied.

## Policies

Global policy: `~/.pi/agent/extensions/bash-guard/policy.json`

Project policy: `<project>/.pi/bash-guard.json` (loaded only for trusted projects)

```json
{
  "version": 2,
  "ownership": {
    "edit": [
      "./generated/**",
      "!./generated/protected/**"
    ],
    "full": [
      "/absolute/trusted/scripts/**",
      "!/absolute/trusted/scripts/untrusted/**"
    ]
  },
  "secrets": ["./private/**"],
  "commands": [
    { "name": "project-inspect", "category": "read", "note": "local inspection helper" },
    { "name": "legacy-deploy", "category": "remote" }
  ]
}
```

Ownership lists use ordered Gitignore-style patterns. The last matching positive or `!` negative controls membership in that class. Full is evaluated first; an exclusion or miss falls through to edit, then to the read-only default. Global lists are evaluated before trusted local lists.

Run `/bash-guard`, choose global or local, and the policy opens directly in `$VISUAL`, `$EDITOR`, or `nano`. There is no policy-management submenu. Custom command categories are edited in the same file: `allow`, `read`, `create`, `edit`, `delete`, `execute`, `remote`, and `deny`.

## Approval choices

A flagged operation offers one-time approval or refusal with an optional follow-up comment. Compound shell input is inspected in lexical shell order and each command requiring permission is presented separately. Choosing persistent ownership asks only for global or local scope, appends the exact path to the required edit/full list, and opens the policy in the external editor at that entry. Literal standalone unowned deletion may be replaced with `gio trash`.

Menus use `j`/`k` or arrow keys to move, `l` or Enter to accept, and `h` to go back one level. Long command/reason details keep the options visible; use Ctrl-U/Ctrl-D or `g`/`G` to inspect every detail page. Esc and Ctrl-C cancel the entire flow.

## Limits

This is static policy enforcement, not a sandbox. Full ownership of a script means its opaque side effects are trusted. Generic tools are guarded only when their public input contains recognizable path fields. Automatic ownership is recorded only for successful creations that can be attributed conservatively.
