import { isAbsolute } from "node:path";
import { quote as shellQuote } from "shell-quote";
import { canonicalPath } from "./path-utils.ts";
import { knownShellValue, shellParameterNames, type ShellEnvironment } from "./shell-context.ts";

/** Deliberately not a general process.env lookup. List-valued paths and credentials are excluded. */
export const INHERITED_PATH_VARIABLES = [
  "HOME", "OLDPWD", "TMPDIR", "TMP", "TEMP", "XDG_CONFIG_HOME", "XDG_CACHE_HOME",
  "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR", "PI_CODING_AGENT_DIR", "PI_CODING_AGENT_SESSION_DIR",
] as const;
const DEFAULT_IFS = " \t\n";

export interface BashContextSnapshot {
  readonly cwd: string;
  readonly environment: Readonly<ShellEnvironment>;
  readonly assertions: Readonly<ShellEnvironment>;
}

function acceptablePath(value: string): boolean {
  return value.length <= 4096 && (value === "" || isAbsolute(value)) && knownShellValue(value) && !/[\x00-\x1f\x7f*?\[\]]/.test(value);
}

/** Snapshot only reviewed inputs. The same assumptions are checked at execution, not guessed. */
export function captureBashContext(command: string, cwd: string, home: string, inherited: NodeJS.ProcessEnv): BashContextSnapshot {
  const references = new Set(["HOME", ...shellParameterNames(command)]);
  // Bash builtins/utilities also consume some variables without an explicit $ reference.
  if (/\bmktemp\b/.test(command)) references.add("TMPDIR");
  if (/\bcd\s+-\s*(?:[;&\n]|$)/.test(command)) references.add("OLDPWD");
  const physical = canonicalPath(cwd);
  const inheritedPwd = inherited.PWD;
  const logical = inheritedPwd && acceptablePath(inheritedPwd) && canonicalPath(inheritedPwd) === physical ? inheritedPwd : physical;
  const environment: ShellEnvironment = { HOME: home, PWD: logical, IFS: DEFAULT_IFS, CDPATH: undefined };
  const assertions: ShellEnvironment = { PWD: logical, IFS: DEFAULT_IFS };
  for (const key of INHERITED_PATH_VARIABLES) {
    if (!references.has(key)) continue;
    const value = inherited[key];
    if (value === undefined || acceptablePath(value)) {
      environment[key] = value;
      assertions[key] = value;
    } else environment[key] = `$${key}`;
  }
  // CDPATH changes bare relative cd operands. Nonempty path lists are not interpreted.
  const cdpath = inherited.CDPATH;
  if (cdpath === undefined || cdpath === "") {
    environment.CDPATH = cdpath;
    assertions.CDPATH = cdpath;
  } else environment.CDPATH = "$CDPATH";
  return Object.freeze({ cwd: physical, environment: Object.freeze(environment), assertions: Object.freeze(assertions) });
}

/**
 * tool_call runs before Pi's command prefix/spawn hook. Verification must run in the eventual
 * shell, after that setup, and abort before the submitted command if any assumption differs.
 * It does not discover values, eval code, export variables, or replace the execution backend.
 */
export function verifyBashContext(command: string, snapshot: BashContextSnapshot): string {
  const checks = [
    `command -p test "$(command -p pwd -P)" = ${shellQuote([snapshot.cwd])}`,
    "case $- in *P*) false ;; *) true ;; esac",
    "! command -p shopt -qo posix",
  ];
  for (const [key, value] of Object.entries(snapshot.assertions)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) throw new Error("Invalid shell context assertion name");
    // Matching text alone is insufficient: readonly, integer, array, or nameref attributes change assignments.
    checks.push(`case "$(command -p declare -p ${key} 2>/dev/null)" in ''|'declare -- '*|'declare -x '*) true ;; *) false ;; esac`);
    checks.push(value === undefined
      ? `command -p test "\${${key}+x}" != x`
      : `command -p test "\${${key}+x}" = x && command -p test "$${key}" = ${shellQuote([value])}`);
  }
  const message = "bash-guard: shell context changed after approval; command not executed. Reconcile the shell startup/spawn setup before retrying.";
  return `# bash-guard: verify analyzed shell context (no environment changes)\nif ! { ${checks.join(" && ")}; }; then command -p printf '%s\\n' ${shellQuote([message])} >&2; exit 125; fi\n${command}`;
}
