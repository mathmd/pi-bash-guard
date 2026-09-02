import { canonicalPath, resolvePath } from "./path-utils.ts";

const TEXT_PATTERNS: Array<[RegExp, string]> = [
  [/\b(?:mkfs(?:\.\w+)?|newfs_\w+|wipefs)\b/, "filesystem formatting or signature destruction"],
  [/\bdd\b[^\n]*\bof=\/dev\//, "raw device write"],
  [/\b(?:parted|fdisk|gdisk|sgdisk)\b/, "partition-table mutation"],
  [/\b(?:shutdown|reboot|halt|poweroff)\b/, "system power operation"],
  [/:\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:/, "fork bomb"],
  [/\bgit\s+push\b[^\n]*(?:--force(?:-with-lease)?|-f)(?:\s|$)/, "forced remote history rewrite"],
  [/\bgit\s+reset\b[^\n]*--hard\b/, "destructive Git reset"],
  [/\bgit\s+clean\b[^\n]*-[A-Za-z]*f/, "destructive removal of untracked files"],
  [/\bterraform\s+destroy\b|\btofu\s+destroy\b/, "infrastructure teardown"],
  [/\b(?:rm|rmdir)\b[^\n]*(?:\s|^)(?:\/|~)(?:\s|$)/, "deletion of a filesystem root or home"],
];

/** Legacy text fallback for languages without a syntax-aware screener. */
export function catastrophicTextReason(source: string): string | undefined {
  for (const [pattern, reason] of TEXT_PATTERNS) if (pattern.test(source)) return reason;
  return undefined;
}

function shellSyntaxOutsideData(source: string): string {
  let result = "";
  let quote: "'" | '"' | undefined;
  let escaped = false;
  let comment = false;
  for (let index = 0; index < source.length; index++) {
    const char = source[index]!;
    if (comment) {
      result += char === "\n" ? "\n" : " ";
      if (char === "\n") comment = false;
      continue;
    }
    if (escaped) { result += " "; escaped = false; continue; }
    if (char === "\\" && quote !== "'") { result += " "; escaped = true; continue; }
    if (quote) {
      result += char === quote ? char : " ";
      if (char === quote) quote = undefined;
      continue;
    }
    if (char === "'" || char === '"') { quote = char; result += char; continue; }
    if (char === "#" && (index === 0 || /[\s;|&()]/.test(source[index - 1]!))) { comment = true; result += " "; continue; }
    result += char;
  }
  return result;
}

export function containsUnquotedForkBomb(source: string): boolean {
  return /:\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:/.test(shellSyntaxOutsideData(source));
}

/** Match hazards only after shell parsing has identified an executable and its arguments. */
export function catastrophicInvocation(command: string, args: string[], cwd: string, home: string): string | undefined {
  if (/^(?:mkfs(?:\.\w+)?|newfs_\w+|wipefs)$/.test(command)) return "filesystem formatting or signature destruction";
  if (["parted", "fdisk", "gdisk", "sgdisk"].includes(command)) return "partition-table mutation";
  if (["shutdown", "reboot", "halt", "poweroff"].includes(command)) return "system power operation";
  if (command === "dd" && args.some((arg) => /^of=\/dev\//.test(arg))) return "raw device write";
  if (["terraform", "tofu"].includes(command) && args.find((arg) => !arg.startsWith("-")) === "destroy") return "infrastructure teardown";
  if (["rm", "rmdir"].includes(command)) {
    for (const arg of args.filter((value) => !value.startsWith("-"))) {
      const path = canonicalPath(resolvePath(arg, cwd, home));
      if (path === "/" || path === canonicalPath(home)) return "deletion of a filesystem root or home";
    }
  }
  return undefined;
}
