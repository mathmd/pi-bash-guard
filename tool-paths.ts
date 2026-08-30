import type { AccessKind } from "./types.ts";
import { looksLikePath } from "./path-utils.ts";

const PATH_KEYS = /(?:^|_)(?:path|file|filename|directory|dir|cwd|root|target|destination|dest|output)(?:$|_)/i;
const READ_KEYS = /(?:source|input|read|search|root|cwd)/i;

export function genericPathInputs(
  input: unknown,
  key = "",
  out: Array<{ value: string; kind: AccessKind }> = [],
  forcedKind?: AccessKind,
): Array<{ value: string; kind: AccessKind }> {
  if (typeof input === "string") {
    if (PATH_KEYS.test(key) && looksLikePath(input)) {
      out.push({ value: input, kind: forcedKind ?? (READ_KEYS.test(key) ? "read" : "unknown") });
    }
    return out;
  }
  if (Array.isArray(input)) {
    for (const value of input) genericPathInputs(value, key, out, forcedKind);
    return out;
  }
  if (input && typeof input === "object") {
    for (const [childKey, value] of Object.entries(input as Record<string, unknown>)) {
      genericPathInputs(value, childKey, out, forcedKind);
    }
  }
  return out;
}
