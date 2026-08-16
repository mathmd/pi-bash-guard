import { spawnSync } from "node:child_process";
import { basename } from "node:path";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { parse as shellParse } from "shell-quote";

export interface EditorInvocation {
  command: string;
  args: string[];
}

export function editorInvocation(editor: string, path: string, line = 1): EditorInvocation {
  const words = (shellParse(editor) as unknown[]).filter((value): value is string => typeof value === "string");
  const command = words[0] || (process.platform === "win32" ? "notepad" : "nano");
  const args = words.slice(1);
  const name = basename(command).toLowerCase();
  if (["nvim", "vim", "vi", "view", "nvim-qt", "gvim"].includes(name)) args.push(`+${line}`, path);
  else if (["code", "codium", "code-insiders"].includes(name)) args.push("--goto", `${path}:${line}:1`);
  else if (["hx", "helix"].includes(name)) args.push(`${path}:${line}:1`);
  else if (name === "nano") args.push(`+${line},1`, path);
  else args.push(path);
  return { command, args };
}

export async function openPolicyInEditor(ctx: ExtensionContext, path: string, line = 1): Promise<boolean> {
  if (ctx.mode !== "tui") {
    ctx.ui.notify(`Open this policy in your editor: ${path}:${line}`, "warning");
    return false;
  }
  const editor = process.env.VISUAL || process.env.EDITOR || (process.platform === "win32" ? "notepad" : "nano");
  const invocation = editorInvocation(editor, path, line);
  const status = await ctx.ui.custom<number>((tui, theme, _keybindings, done) => {
    let launched = false;
    queueMicrotask(() => {
      if (launched) return;
      launched = true;
      tui.stop();
      let exitStatus = 1;
      try {
        exitStatus = spawnSync(invocation.command, invocation.args, { stdio: "inherit" }).status ?? 1;
      } finally {
        tui.start();
        tui.requestRender(true);
      }
      done(exitStatus);
    });
    return {
      render: () => [theme.fg("muted", `Opening ${path} in ${invocation.command}…`)],
      invalidate: () => {},
      handleInput: () => {},
    };
  });
  return status === 0;
}
