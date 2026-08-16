import { spawn } from "node:child_process";

export interface NotificationInvocation {
  command: string;
  args: string[];
  env?: NodeJS.ProcessEnv;
}

export function notificationInvocation(
  platform: NodeJS.Platform,
  title: string,
  body: string,
  baseEnv: NodeJS.ProcessEnv = process.env,
): NotificationInvocation | undefined {
  const conciseBody = body.slice(0, 500);
  if (platform === "linux") {
    return { command: "notify-send", args: ["--app-name=Pi", title, conciseBody] };
  }
  if (platform === "darwin") {
    return {
      command: "osascript",
      args: [
        "-e", "on run argv",
        "-e", "display notification (item 2 of argv) with title (item 1 of argv)",
        "-e", "end run",
        title,
        conciseBody,
      ],
    };
  }
  if (platform === "win32") {
    const script = [
      "Add-Type -AssemblyName System.Windows.Forms",
      "Add-Type -AssemblyName System.Drawing",
      "$n=New-Object System.Windows.Forms.NotifyIcon",
      "$n.Icon=[System.Drawing.SystemIcons]::Information",
      "$n.BalloonTipTitle=$env:PI_NOTIFICATION_TITLE",
      "$n.BalloonTipText=$env:PI_NOTIFICATION_BODY",
      "$n.Visible=$true",
      "$n.ShowBalloonTip(5000)",
      "Start-Sleep -Milliseconds 5500",
      "$n.Dispose()",
    ].join(";");
    return {
      command: "powershell.exe",
      args: ["-NoProfile", "-NonInteractive", "-Command", script],
      env: { ...baseEnv, PI_NOTIFICATION_TITLE: title, PI_NOTIFICATION_BODY: conciseBody },
    };
  }
  return undefined;
}

export function sendSystemNotification(title: string, body: string): void {
  const invocation = notificationInvocation(process.platform, title, body);
  if (!invocation) {
    process.stderr.write("\u0007");
    return;
  }
  try {
    const child = spawn(invocation.command, invocation.args, {
      detached: true,
      stdio: "ignore",
      ...(invocation.env ? { env: invocation.env } : {}),
    });
    child.on("error", () => { /* Desktop notifications are best-effort. */ });
    child.unref();
  } catch { /* Desktop notifications are best-effort. */ }
}
