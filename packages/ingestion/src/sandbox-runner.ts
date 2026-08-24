import { spawn } from 'node:child_process';
import type { SandboxExecutionOptions, SandboxExecutionResult } from './types.js';

export const SENSITIVE_ENV_PATTERNS = [
  /^AWS_/i,
  /^GITHUB_/i,
  /^GH_/i,
  /^AZURE_/i,
  /^GOOGLE_/i,
  /^GCP_/i,
  /^SSH_/i,
  /SECRET/i,
  /API_KEY/i,
  /TOKEN/i,
  /PASSWORD/i,
  /PRIVATE_KEY/i,
  /CREDENTIAL/i,
];

export function scrubEnvironment(
  baseEnv: NodeJS.ProcessEnv = process.env,
  customEnv: Record<string, string> = {}
): Record<string, string> {
  const safeEnv: Record<string, string> = {};

  // Standard safe system variables
  const safeSystemVars = ['PATH', 'PATHEXT', 'SYSTEMROOT', 'TEMP', 'TMP', 'HOME', 'USERPROFILE', 'NODE_ENV'];

  for (const [key, value] of Object.entries(baseEnv)) {
    if (!value) continue;

    const isExplicitlySafe = safeSystemVars.includes(key.toUpperCase());
    const isSensitive = SENSITIVE_ENV_PATTERNS.some((pattern) => pattern.test(key));

    if (isExplicitlySafe || !isSensitive) {
      safeEnv[key] = value;
    }
  }

  // Merge custom environment overrides
  for (const [key, value] of Object.entries(customEnv)) {
    safeEnv[key] = value;
  }

  return safeEnv;
}

export class SandboxRunner {
  private readonly defaultTimeoutMs: number;
  private readonly defaultMaxBufferBytes: number;

  constructor(options: { defaultTimeoutMs?: number; defaultMaxBufferBytes?: number } = {}) {
    this.defaultTimeoutMs = options.defaultTimeoutMs ?? 60_000;
    this.defaultMaxBufferBytes = options.defaultMaxBufferBytes ?? 10 * 1024 * 1024; // 10MB
  }

  public async runInSandbox(
    command: string,
    args: string[],
    cwd: string,
    options: SandboxExecutionOptions = {}
  ): Promise<SandboxExecutionResult> {
    const timeoutMs = options.timeoutMs ?? this.defaultTimeoutMs;
    const maxBuffer = options.maxBufferSizeBytes ?? this.defaultMaxBufferBytes;
    const safeEnv = scrubEnvironment(process.env, options.env ?? {});

    const startTime = Date.now();

    return new Promise((resolve) => {
      let stdout = '';
      let stderr = '';
      let timedOut = false;
      let isResolved = false;

      const child = spawn(command, args, {
        cwd,
        env: safeEnv,
        stdio: ['ignore', 'pipe', 'pipe'],
        shell: false,
      });

      const timer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGTERM');
        setTimeout(() => {
          if (!child.killed) {
            child.kill('SIGKILL');
          }
        }, 2000);
      }, timeoutMs);

      child.stdout.on('data', (chunk: Buffer) => {
        if (stdout.length + chunk.length <= maxBuffer) {
          stdout += chunk.toString('utf-8');
        }
      });

      child.stderr.on('data', (chunk: Buffer) => {
        if (stderr.length + chunk.length <= maxBuffer) {
          stderr += chunk.toString('utf-8');
        }
      });

      child.on('error', (err) => {
        clearTimeout(timer);
        if (!isResolved) {
          isResolved = true;
          resolve({
            exitCode: -1,
            stdout,
            stderr: `${stderr}\nProcess error: ${err.message}`,
            durationMs: Date.now() - startTime,
            timedOut,
          });
        }
      });

      child.on('close', (code) => {
        clearTimeout(timer);
        if (!isResolved) {
          isResolved = true;
          resolve({
            exitCode: code ?? (timedOut ? -1 : 0),
            stdout,
            stderr,
            durationMs: Date.now() - startTime,
            timedOut,
          });
        }
      });
    });
  }
}
