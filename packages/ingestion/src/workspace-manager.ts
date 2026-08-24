import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { randomUUID } from 'node:crypto';
import type { EphemeralWorkspace } from './types.js';

export class SecuritySandboxError extends Error {
  constructor(message: string) {
    super(`[Security Sandbox Violation] ${message}`);
    this.name = 'SecuritySandboxError';
  }
}

export interface WorkspaceManagerOptions {
  baseTempDir?: string;
  prefix?: string;
}

export class DefaultEphemeralWorkspace implements EphemeralWorkspace {
  public readonly id: string;
  public readonly workspaceDir: string;
  private isCleanedUp = false;

  constructor(id: string, workspaceDir: string) {
    this.id = id;
    this.workspaceDir = path.resolve(workspaceDir);
  }

  public resolveSafePath(relativePath: string): string {
    if (this.isCleanedUp) {
      throw new SecuritySandboxError('Cannot access workspace after cleanup');
    }

    // Clean relative path and resolve against workspace directory
    const normalizedRelative = path.normalize(relativePath).replace(/^(\.\.(\/|\\|$))+/, '');
    const resolvedPath = path.resolve(this.workspaceDir, normalizedRelative);

    // Enforce that resolved path starts with workspaceDir
    const normalizedRoot = this.workspaceDir.endsWith(path.sep)
      ? this.workspaceDir
      : this.workspaceDir + path.sep;

    if (resolvedPath !== this.workspaceDir && !resolvedPath.startsWith(normalizedRoot)) {
      throw new SecuritySandboxError(
        `Path traversal escape detected: "${relativePath}" resolves to "${resolvedPath}" which is outside workspace "${this.workspaceDir}"`
      );
    }

    return resolvedPath;
  }

  public async readSafeFile(relativePath: string): Promise<string> {
    const safePath = this.resolveSafePath(relativePath);

    try {
      const stat = await fs.lstat(safePath);
      if (stat.isSymbolicLink()) {
        const realTarget = await fs.realpath(safePath);
        const normalizedRoot = this.workspaceDir.endsWith(path.sep)
          ? this.workspaceDir
          : this.workspaceDir + path.sep;
        if (realTarget !== this.workspaceDir && !realTarget.startsWith(normalizedRoot)) {
          throw new SecuritySandboxError(
            `Symlink escape detected: "${relativePath}" points to "${realTarget}" outside workspace`
          );
        }
      }

      return await fs.readFile(safePath, 'utf-8');
    } catch (err: unknown) {
      if (err instanceof SecuritySandboxError) {
        throw err;
      }
      throw new Error(`Failed to read file "${relativePath}": ${(err as Error).message}`);
    }
  }

  public async listFilesSafe(subDir: string = ''): Promise<string[]> {
    const safeBase = this.resolveSafePath(subDir);
    const results: string[] = [];

    async function walk(currentDir: string, relativePrefix: string, workspaceRoot: string) {
      let entries;
      try {
        entries = await fs.readdir(currentDir, { withFileTypes: true });
      } catch {
        return;
      }

      for (const entry of entries) {
        if (entry.name === '.git' || entry.name === 'node_modules') {
          continue;
        }

        const entryPath = path.join(currentDir, entry.name);
        const relPath = relativePrefix ? `${relativePrefix}/${entry.name}` : entry.name;

        if (entry.isSymbolicLink()) {
          try {
            const realTarget = await fs.realpath(entryPath);
            const normalizedRoot = workspaceRoot.endsWith(path.sep)
              ? workspaceRoot
              : workspaceRoot + path.sep;
            if (realTarget !== workspaceRoot && !realTarget.startsWith(normalizedRoot)) {
              // Skip or report malicious symlinks
              continue;
            }
          } catch {
            continue;
          }
        }

        if (entry.isDirectory()) {
          await walk(entryPath, relPath, workspaceRoot);
        } else if (entry.isFile()) {
          results.push(relPath.replace(/\\/g, '/'));
        }
      }
    }

    await walk(safeBase, subDir ? subDir.replace(/\\/g, '/') : '', this.workspaceDir);
    return results;
  }

  public async cleanup(): Promise<void> {
    if (this.isCleanedUp) {
      return;
    }

    try {
      await fs.rm(this.workspaceDir, { recursive: true, force: true });
    } finally {
      this.isCleanedUp = true;
    }
  }
}

export class WorkspaceManager {
  private readonly baseTempDir: string;
  private readonly prefix: string;

  constructor(options: WorkspaceManagerOptions = {}) {
    this.baseTempDir = options.baseTempDir ?? path.join(os.tmpdir(), 'ai-security-architect');
    this.prefix = options.prefix ?? 'scan-workspace-';
  }

  public async createWorkspace(): Promise<EphemeralWorkspace> {
    const id = randomUUID();
    const workspaceDir = path.join(this.baseTempDir, `${this.prefix}${id}`);

    await fs.mkdir(workspaceDir, { recursive: true });
    return new DefaultEphemeralWorkspace(id, workspaceDir);
  }
}
