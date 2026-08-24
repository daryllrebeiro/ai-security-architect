import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import type { EphemeralWorkspace, RepositorySource } from './types.js';
import { SandboxRunner } from './sandbox-runner.js';

export interface RepositoryAcquirer {
  supports(source: RepositorySource): boolean;
  acquire(source: RepositorySource, workspace: EphemeralWorkspace): Promise<void>;
}

export class LocalRepositoryAcquirer implements RepositoryAcquirer {
  public supports(source: RepositorySource): boolean {
    return source.type === 'LOCAL_DIRECTORY';
  }

  public async acquire(source: RepositorySource, workspace: EphemeralWorkspace): Promise<void> {
    if (source.type !== 'LOCAL_DIRECTORY') {
      throw new Error(`LocalRepositoryAcquirer only supports LOCAL_DIRECTORY, received: ${source.type}`);
    }

    const sourcePath = path.resolve(source.path);

    try {
      const stat = await fs.stat(sourcePath);
      if (!stat.isDirectory()) {
        throw new Error(`Source path is not a directory: ${sourcePath}`);
      }
    } catch (err: unknown) {
      throw new Error(`Cannot access source directory "${sourcePath}": ${(err as Error).message}`);
    }

    await this.copyRecursive(sourcePath, workspace.workspaceDir);
  }

  private async copyRecursive(srcDir: string, destDir: string): Promise<void> {
    const entries = await fs.readdir(srcDir, { withFileTypes: true });

    for (const entry of entries) {
      if (entry.name === '.git' || entry.name === 'node_modules' || entry.name === '.venv') {
        continue;
      }

      const srcPath = path.join(srcDir, entry.name);
      const destPath = path.join(destDir, entry.name);

      if (entry.isDirectory()) {
        await fs.mkdir(destPath, { recursive: true });
        await this.copyRecursive(srcPath, destPath);
      } else if (entry.isFile()) {
        await fs.copyFile(srcPath, destPath);
      }
    }
  }
}

export class GitRepositoryAcquirer implements RepositoryAcquirer {
  private readonly sandboxRunner: SandboxRunner;

  constructor(sandboxRunner?: SandboxRunner) {
    this.sandboxRunner = sandboxRunner ?? new SandboxRunner();
  }

  public supports(source: RepositorySource): boolean {
    return source.type === 'GIT_REMOTE';
  }

  public async acquire(source: RepositorySource, workspace: EphemeralWorkspace): Promise<void> {
    if (source.type !== 'GIT_REMOTE') {
      throw new Error(`GitRepositoryAcquirer only supports GIT_REMOTE, received: ${source.type}`);
    }

    const args = [
      'clone',
      '--depth',
      '1',
      '--branch',
      source.branch,
      '--single-branch',
      source.url,
      workspace.workspaceDir,
    ];

    const result = await this.sandboxRunner.runInSandbox('git', args, workspace.workspaceDir, {
      timeoutMs: 120_000,
    });

    if (result.exitCode !== 0) {
      throw new Error(`Git clone failed with code ${result.exitCode}: ${result.stderr || result.stdout}`);
    }
  }
}

export class RepositoryAcquisitionManager {
  private readonly acquirers: RepositoryAcquirer[];

  constructor(acquirers?: RepositoryAcquirer[]) {
    this.acquirers = acquirers ?? [
      new LocalRepositoryAcquirer(),
      new GitRepositoryAcquirer(),
    ];
  }

  public async acquire(source: RepositorySource, workspace: EphemeralWorkspace): Promise<void> {
    const acquirer = this.acquirers.find((a) => a.supports(source));
    if (!acquirer) {
      throw new Error(`No repository acquirer registered for source type "${source.type}"`);
    }

    await acquirer.acquire(source, workspace);
  }
}
