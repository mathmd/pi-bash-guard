import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import type { LoadExtensionsResult } from "@earendil-works/pi-coding-agent";

export const project = dirname(dirname(fileURLToPath(import.meta.url)));
export const piDist = dirname(fileURLToPath(import.meta.resolve("@earendil-works/pi-coding-agent")));
export const piRequire = createRequire(join(piDist, "index.js"));

export async function loadFixtureExtension(path: string, cwd: string): Promise<LoadExtensionsResult> {
  // The development dependency supplies Pi's real loader and its injected runtime aliases.
  // Production installs use the host Pi instead; no global installation path is assumed here.
  const { loadExtensions } = await import(pathToFileURL(join(piDist, "core/extensions/loader.js")).href);
  return loadExtensions([path], cwd);
}
