import { describe, it, expect, afterEach } from 'vitest';
import * as path from 'node:path';
import * as fs from 'node:fs/promises';
import {
  WorkspaceManager,
  SecuritySandboxError,
  SandboxRunner,
  scrubEnvironment,
  RepositoryAcquisitionManager,
  ScanJobCoordinator,
  type EphemeralWorkspace,
} from '../src/index.js';

describe('Phase 1 - Ingestion & Sandboxing Architecture', () => {
  let createdWorkspaces: EphemeralWorkspace[] = [];

  afterEach(async () => {
    for (const ws of createdWorkspaces) {
      await ws.cleanup().catch(() => {});
    }
    createdWorkspaces = [];
  });

  describe('WorkspaceManager & Path Sandboxing', () => {
    it('creates an isolated workspace and cleans up reliably', async () => {
      const manager = new WorkspaceManager();
      const workspace = await manager.createWorkspace();
      createdWorkspaces.push(workspace);

      expect(workspace.id).toBeDefined();
      expect(workspace.workspaceDir).toBeDefined();

      const existsBefore = await fs
        .stat(workspace.workspaceDir)
        .then(() => true)
        .catch(() => false);
      expect(existsBefore).toBe(true);

      // Write test file
      const safeFilePath = workspace.resolveSafePath('sub/test.txt');
      await fs.mkdir(path.dirname(safeFilePath), { recursive: true });
      await fs.writeFile(safeFilePath, 'hello security architect');

      const content = await workspace.readSafeFile('sub/test.txt');
      expect(content).toBe('hello security architect');

      const files = await workspace.listFilesSafe();
      expect(files).toContain('sub/test.txt');

      await workspace.cleanup();
      const existsAfter = await fs
        .stat(workspace.workspaceDir)
        .then(() => true)
        .catch(() => false);
      expect(existsAfter).toBe(false);
    });

    it('blocks directory traversal escapes outside the workspace', async () => {
      const manager = new WorkspaceManager();
      const workspace = await manager.createWorkspace();
      createdWorkspaces.push(workspace);

      expect(() => {
        workspace.resolveSafePath('../../../../etc/passwd');
      }).not.toThrow(); // Normalized relative path strips leading `../` to prevent escape

      const resolved = workspace.resolveSafePath('../../../../etc/passwd');
      expect(resolved.startsWith(workspace.workspaceDir)).toBe(true);
    });
  });

  describe('SandboxRunner & Environment Scrubbing', () => {
    it('scrubs sensitive credentials from process environment', () => {
      const mockEnv = {
        PATH: '/usr/bin:/bin',
        NODE_ENV: 'test',
        AWS_SECRET_ACCESS_KEY: 'AKIAIOSFODNN7EXAMPLE',
        AWS_SESSION_TOKEN: 'session-token-xyz',
        GITHUB_TOKEN: 'ghp_secretToken1234567890',
        GH_TOKEN: 'gh_secret',
        CUSTOM_SECRET_KEY: 'secret123',
        SAFE_APP_CONFIG: 'production_tier',
      };

      const scrubbed = scrubEnvironment(mockEnv, { EXTRA_ARG: 'safe' });

      expect(scrubbed.PATH).toBe('/usr/bin:/bin');
      expect(scrubbed.NODE_ENV).toBe('test');
      expect(scrubbed.SAFE_APP_CONFIG).toBe('production_tier');
      expect(scrubbed.EXTRA_ARG).toBe('safe');

      expect(scrubbed.AWS_SECRET_ACCESS_KEY).toBeUndefined();
      expect(scrubbed.AWS_SESSION_TOKEN).toBeUndefined();
      expect(scrubbed.GITHUB_TOKEN).toBeUndefined();
      expect(scrubbed.GH_TOKEN).toBeUndefined();
      expect(scrubbed.CUSTOM_SECRET_KEY).toBeUndefined();
    });

    it('executes safe commands and captures output in sandbox', async () => {
      const runner = new SandboxRunner();
      const result = await runner.runInSandbox(process.execPath, ['-e', 'console.log("SANDBOX_OK")'], process.cwd());

      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain('SANDBOX_OK');
      expect(result.timedOut).toBe(false);
    });

    it('enforces execution timeouts on long-running processes', async () => {
      const runner = new SandboxRunner();
      const result = await runner.runInSandbox(
        process.execPath,
        ['-e', 'setTimeout(() => {}, 5000)'],
        process.cwd(),
        { timeoutMs: 500 }
      );

      expect(result.timedOut).toBe(true);
    });
  });

  describe('RepositoryAcquisitionManager', () => {
    it('acquires local fixture into ephemeral workspace', async () => {
      const manager = new WorkspaceManager();
      const workspace = await manager.createWorkspace();
      createdWorkspaces.push(workspace);

      const acquirer = new RepositoryAcquisitionManager();
      const fixturePath = path.resolve('fixtures/001-ssrf-iam-s3');

      await acquirer.acquire(
        {
          type: 'LOCAL_DIRECTORY',
          path: fixturePath,
        },
        workspace
      );

      const files = await workspace.listFilesSafe();
      expect(files).toContain('k8s/deployment.yaml');
      expect(files).toContain('terraform/alb.tf');
      expect(files).toContain('terraform/iam.tf');
      expect(files).toContain('terraform/s3.tf');
      expect(files).toContain('src/main/java/com/enterprise/order/OrderController.java');

      const javaContent = await workspace.readSafeFile('src/main/java/com/enterprise/order/OrderController.java');
      expect(javaContent).toContain('OrderController');
    });
  });

  describe('ScanJobCoordinator Lifecycle', () => {
    it('manages end-to-end scan lifecycle and triggers pipeline hooks', async () => {
      const coordinator = new ScanJobCoordinator();
      const fixturePath = path.resolve('fixtures/001-ssrf-iam-s3');

      const events: string[] = [];
      coordinator.on('job:status_changed', (j) => {
        events.push(j.status);
      });

      const job = coordinator.createJob({
        tenantId: 'tenant-test-01',
        source: {
          type: 'LOCAL_DIRECTORY',
          path: fixturePath,
        },
      });

      expect(job.status).toBe('QUEUED');

      let analyzedFilesCount = 0;
      const completedJob = await coordinator.executeScan(job.id, async (_j, ws) => {
        const files = await ws.listFilesSafe();
        analyzedFilesCount = files.length;
      });

      expect(completedJob.status).toBe('COMPLETED');
      expect(completedJob.progressPercentage).toBe(100);
      expect(analyzedFilesCount).toBeGreaterThanOrEqual(4);
      expect(events).toContain('ACQUIRING');
      expect(events).toContain('SANDBOXING');
      expect(events).toContain('ANALYZING');
      expect(events).toContain('COMPLETED');
    });

    it('gracefully handles and transitions to FAILED when source is invalid', async () => {
      const coordinator = new ScanJobCoordinator();
      const job = coordinator.createJob({
        tenantId: 'tenant-test-01',
        source: {
          type: 'LOCAL_DIRECTORY',
          path: './non-existent-directory-xyz-123',
        },
      });

      const failedJob = await coordinator.executeScan(job.id);
      expect(failedJob.status).toBe('FAILED');
      expect(failedJob.error).toBeDefined();
    });
  });
});
