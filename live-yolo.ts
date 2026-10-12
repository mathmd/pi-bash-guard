import { createHash, randomBytes } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { createConnection, createServer, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { canonicalPath } from "./path-utils.ts";

const LIMIT = 4096;
const TIMEOUT = 1000;
const MAX_DEPTH = 8;

/** Rendezvous data is private guard state, never an ownership grant or a saved YOLO setting. */
export function yoloRuntimeDirectory(): string {
  return join(tmpdir(), `pi-bash-guard-${process.getuid?.() ?? "user"}`);
}

export function isYoloControlPath(path: string): boolean {
  const root = canonicalPath(yoloRuntimeDirectory());
  const value = canonicalPath(path);
  return value === root || value.startsWith(root + sep);
}

function recordPath(sessionFile: string): string {
  return join(yoloRuntimeDirectory(), createHash("sha256").update(resolve(sessionFile)).digest("hex") + ".json");
}

function privateEntry(path: string, directory = false): boolean {
  const stat = lstatSync(path);
  return (directory ? stat.isDirectory() : stat.isFile()) && (stat.mode & 0o077) === 0 &&
    (process.getuid === undefined || stat.uid === process.getuid());
}

interface Endpoint { version: 1; sessionFile: string; socket: string; token: string }

function endpointFor(sessionFile: string): Endpoint | undefined {
  try {
    if (!privateEntry(yoloRuntimeDirectory(), true)) return;
    const file = recordPath(sessionFile);
    if (!privateEntry(file) || lstatSync(file).size > LIMIT) return;
    const value = JSON.parse(readFileSync(file, "utf8"));
    if (value.version !== 1 || value.sessionFile !== resolve(sessionFile) ||
        typeof value.socket !== "string" || typeof value.token !== "string" ||
        !/^[a-f0-9]{32}\.sock$/.test(value.socket) || !/^[a-f0-9]{64}$/.test(value.token)) return;
    return value;
  } catch { return; }
}

/** No positive cache: an absent, dead, malformed, or unresponsive authority is strict. */
export function queryParentYolo(sessionFile: string, depth = 0): Promise<boolean> {
  const endpoint = endpointFor(sessionFile);
  if (!endpoint || depth >= MAX_DEPTH) return Promise.resolve(false);
  return new Promise((done) => {
    let settled = false;
    let data = "";
    const socket = createConnection(join(yoloRuntimeDirectory(), endpoint.socket));
    const finish = (enabled: boolean) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      done(enabled);
    };
    const timer = setTimeout(() => finish(false), TIMEOUT);
    socket.on("error", () => finish(false));
    socket.on("end", () => finish(false));
    socket.on("connect", () => socket.write(JSON.stringify({ token: endpoint.token, depth }) + "\n"));
    socket.on("data", (chunk) => {
      data += chunk.toString("utf8");
      if (Buffer.byteLength(data) > LIMIT) return finish(false);
      if (!data.includes("\n")) return;
      try {
        const response = JSON.parse(data.slice(0, data.indexOf("\n")));
        finish(response.version === 1 && response.enabled === true);
      } catch { finish(false); }
    });
  });
}

export interface YoloAuthority { close(): Promise<void> }

/** One live authority per parent session. Created lazily at delegation, not in an extension factory. */
export async function createYoloAuthority(sessionFile: string, currentMode: (depth: number) => Promise<boolean>): Promise<YoloAuthority> {
  const root = yoloRuntimeDirectory();
  mkdirSync(root, { recursive: true, mode: 0o700 });
  if (!privateEntry(root, true)) throw new Error("bash-guard runtime directory must be private and owned by the current user");
  const endpoint: Endpoint = { version: 1, sessionFile: resolve(sessionFile), socket: randomBytes(16).toString("hex") + ".sock", token: randomBytes(32).toString("hex") };
  const socketPath = join(root, endpoint.socket);
  if (Buffer.byteLength(socketPath) > 100) throw new Error("bash-guard runtime socket path is too long; use a shorter TMPDIR");
  const file = recordPath(sessionFile);
  const temporary = file + ".tmp-" + randomBytes(8).toString("hex");
  let active = true;
  const connections = new Set<Socket>();
  const server = createServer((socket) => {
    if (!active || connections.size >= 32) { socket.destroy(); return; }
    connections.add(socket);
    socket.setTimeout(TIMEOUT, () => socket.destroy());
    socket.on("error", () => socket.destroy());
    socket.on("close", () => connections.delete(socket));
    let data = "";
    let requested = false;
    socket.on("data", (chunk) => {
      if (requested) return;
      data += chunk.toString("utf8");
      if (Buffer.byteLength(data) > LIMIT) { socket.destroy(); return; }
      if (!data.includes("\n")) return;
      requested = true;
      let request: { token?: string; depth?: number };
      try { request = JSON.parse(data.slice(0, data.indexOf("\n"))); } catch { socket.destroy(); return; }
      if (!request || request.token !== endpoint.token || !Number.isInteger(request.depth) || request.depth! < 0 || request.depth! >= MAX_DEPTH) {
        socket.destroy(); return;
      }
      void currentMode(request.depth! + 1).then((enabled) => {
        socket.end(JSON.stringify({ version: 1, enabled: active && enabled === true }) + "\n");
      }, () => socket.destroy());
    });
  });
  server.on("error", () => { active = false; });
  const close = async () => {
    active = false;
    for (const connection of connections) connection.destroy();
    await new Promise<void>((done) => server.close(() => done()));
    // A reload/replacement may already own the rendezvous name. Never remove its record.
    if (endpointFor(sessionFile)?.token === endpoint.token) unlinkSync(file);
  };
  try {
    await new Promise<void>((done, reject) => {
      server.once("error", reject);
      server.listen(socketPath, () => { server.removeListener("error", reject); done(); });
    });
    server.unref();
    chmodSync(socketPath, 0o600);
    writeFileSync(temporary, JSON.stringify(endpoint), { flag: "wx", mode: 0o600 });
    renameSync(temporary, file);
    return { close };
  } catch (error) {
    await close();
    throw error;
  } finally {
    if (existsSync(temporary)) unlinkSync(temporary);
  }
}
