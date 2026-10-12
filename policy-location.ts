import { isUtf8 } from "node:buffer";
import { randomUUID } from "node:crypto";
import { linkSync, lstatSync, mkdirSync, readFileSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { validatePolicy } from "./policy.ts";

function hasEntry(path: string): boolean {
  try { lstatSync(path); return true; }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

/** Keep permissions in user state, never alongside an arbitrary installed package. */
export function globalPolicyDirectory(agentDir: string): string {
  const directory = join(agentDir, "bash-guard");
  const destination = join(directory, "policy.json");
  const legacy = join(agentDir, "extensions", "bash-guard", "policy.json");
  // An existing destination (including a symlink) always wins. Never revive old grants.
  if (hasEntry(destination) || !hasEntry(legacy)) return directory;
  if (!statSync(legacy).isFile()) throw new Error(`Legacy bash-guard policy must be a regular file: ${legacy}`);
  const contents = readFileSync(legacy);
  try {
    if (!isUtf8(contents)) throw new Error("Policy is not UTF-8");
    validatePolicy(JSON.parse(contents.toString("utf8")));
  }
  catch {
    throw new Error(`Cannot preserve legacy bash-guard policy: ${legacy}. Repair its UTF-8 version-3 JSON or create a valid policy at ${destination}; automatic schema migration is disabled.`);
  }

  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const temporary = join(directory, `policy.json.tmp-${randomUUID()}`);
  writeFileSync(temporary, contents, { flag: "wx", mode: 0o600 });
  try {
    // Publish complete bytes atomically without overwriting another session's policy.
    try { linkSync(temporary, destination); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
  } finally { unlinkSync(temporary); }
  // Leave the legacy file as a backup. New saves only use the destination.
  return directory;
}
