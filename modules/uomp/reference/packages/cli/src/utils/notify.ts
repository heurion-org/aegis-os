import { spawn } from 'child_process';

export interface ConsentNotification {
  title: string;
  body: string;
  url: string;
}

/**
 * Best-effort desktop notification. Never throws and never blocks the MCP
 * bridge if the platform has no notification helper installed.
 */
export function notifyConsentRequest(notification: ConsentNotification): void {
  if (process.env.UOMP_NO_NOTIFY === '1') return;

  if (process.platform === 'linux') {
    run('notify-send', [
      '-a', 'UOMP',
      '-u', 'normal',
      '-i', 'dialog-information',
      notification.title,
      `${notification.body}\n${notification.url}`,
    ]);
    return;
  }

  if (process.platform === 'darwin') {
    run('osascript', [
      '-e',
      `display notification ${appleScriptString(`${notification.body}\n${notification.url}`)} ` +
      `with title ${appleScriptString(notification.title)}`,
    ]);
  }
}

function run(command: string, args: string[]): void {
  try {
    const child = spawn(command, args, {
      detached: true,
      stdio: 'ignore',
    });
    child.on('error', () => {
      // The consent URL is also printed to stderr.
    });
    child.unref();
  } catch {
    // Notification support is optional.
  }
}

function appleScriptString(value: string): string {
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}
