import { spawn, ChildProcess } from 'child_process';
import { existsSync } from 'fs';

const BINARY_NAMES = ['cloudflared', '/home/jz/.local/bin/cloudflared', '/usr/local/bin/cloudflared'];

function findBinary(): string {
  for (const name of BINARY_NAMES) {
    if (existsSync(name)) return name;
  }
  return 'cloudflared';
}

export function startTunnel(port: number, host: string = '127.0.0.1'): Promise<{ url: string; process: ChildProcess }> {
  return new Promise((resolve, reject) => {
    const binary = findBinary();
    const proc = spawn(binary, [
      'tunnel', '--url', `https://${host}:${port}`,
      '--no-tls-verify',
    ], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let resolved = false;

    proc.stdout!.on('data', (chunk: Buffer) => {
      const text = chunk.toString();
      const match = text.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/);
      if (match && !resolved) {
        resolved = true;
        resolve({ url: match[0], process: proc });
      }
    });

    proc.stderr!.on('data', (chunk: Buffer) => {
      const text = chunk.toString();
      const match = text.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/);
      if (match && !resolved) {
        resolved = true;
        resolve({ url: match[0], process: proc });
      }
    });

    proc.on('error', (err: Error) => {
      if (!resolved) {
        resolved = true;
        reject(new Error(`cloudflared failed: ${err.message}. Install: curl -L -o ~/.local/bin/cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 && chmod +x ~/.local/bin/cloudflared`));
      }
    });

    proc.on('exit', (code: number | null) => {
      if (!resolved) {
        resolved = true;
        reject(new Error(`cloudflared exited with code ${code}`));
      }
    });

    setTimeout(() => {
      if (!resolved) {
        resolved = true;
        proc.kill();
        reject(new Error('cloudflared tunnel timed out (15s)'));
      }
    }, 15000);
  });
}
