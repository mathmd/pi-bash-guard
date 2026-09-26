import { existsSync, globSync, lstatSync, realpathSync, statSync } from "node:fs";
import { dirname, isAbsolute, join, normalize, relative, sep } from "node:path";

export function expandHome(value: string, home: string): string {
  if (value === "~") return home;
  if (value.startsWith(`~${sep}`) || value.startsWith("~/")) return `${home}${home.endsWith(sep) ? "" : sep}${value.slice(2)}`;
  return value;
}

export function resolvePath(value: string, cwd: string, home: string): string {
  const expanded = expandHome(value, home);
  // Keep .. until filesystem resolution: link/.. follows the link before traversing its parent.
  return isAbsolute(expanded) ? expanded : `${cwd}${cwd.endsWith(sep) ? "" : sep}${expanded}`;
}

/** Resolve symlinks in the existing part while preserving a missing suffix. */
export function canonicalPath(value: string): string {
  let cursor = value;
  const suffix: string[] = [];
  while (!existsSync(cursor)) {
    const parent = dirname(cursor);
    if (parent === cursor) return normalize(value);
    suffix.unshift(cursor.slice(parent.length + (parent.endsWith(sep) ? 0 : 1)));
    cursor = parent;
  }
  try {
    return normalize(join(realpathSync.native(cursor), ...suffix));
  } catch {
    return normalize(value);
  }
}

export function isWithin(path: string, root: string): boolean {
  const rel = relative(root, path);
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel));
}

export function pathExists(path: string): boolean {
  try {
    lstatSync(path);
    return true;
  } catch {
    return false;
  }
}

export function matchingGlobPaths(pattern: string, limit = 10_000): Set<string> {
  try { return new Set(globSync(pattern).slice(0, limit).map(canonicalPath)); }
  catch { return new Set(); }
}

export function pathIsDirectory(path: string): boolean {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

export function containsGitMetadata(path: string): boolean {
  return normalize(path).split(sep).includes(".git");
}

export function looksLikePath(value: string): boolean {
  if (!value || value.startsWith("-") || value.includes("\n") || /^(?:[A-Za-z][A-Za-z0-9+.-]*):\/\//.test(value)) return false;
  if (value === "." || value === ".." || value.startsWith("./") || value.startsWith("../") ||
      value.startsWith("/") || value.startsWith("~/") || /^[A-Za-z]:[\\/]/.test(value)) return true;
  if (/\s/.test(value)) return false;
  const segment = "[A-Za-z0-9._@%+=,:~-]+";
  return new RegExp(`^${segment}(?:/${segment})+/?$`).test(value);
}

export function globToRegExp(pattern: string): RegExp {
  let out = "^";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === "*") {
      if (pattern[i + 1] === "*") {
        i++;
        if (pattern[i + 1] === "/") { i++; out += "(?:.*/)?"; }
        else out += ".*";
      } else out += "[^/]*";
    } else if (c === "?") out += "[^/]";
    else out += c.replace(/[\\^$+?.()|{}\[\]]/g, "\\$&");
  }
  return new RegExp(`${out}$`);
}

export function patternSpecificity(pattern: string): number {
  return pattern.replace(/[?*]/g, "").length;
}
