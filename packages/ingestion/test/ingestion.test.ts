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
  ScanJobRepository,
  ScanJobQueue,
  ScanJobMetrics,
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
      const logEntries: Array<{ event: string; traceId?: string; tenantId?: string }> = [];
      coordinator.on('job:status_changed', (j) => {
        events.push(j.status);
      });
      coordinator.on('job:log', (entry) => {
        logEntries.push({
          event: entry.event,
          traceId: entry.traceId,
          tenantId: entry.tenantId,
        });
      });

      const job = coordinator.createJob({
        tenantId: 'tenant-test-01',
        source: {
          type: 'LOCAL_DIRECTORY',
          path: fixturePath,
        },
      });

      expect(job.status).toBe('QUEUED');
      expect(job.traceId).toBeDefined();

      let analyzedFilesCount = 0;
      const completedJob = await coordinator.executeScan(job.id, async (_j, ws) => {
        const files = await ws.listFilesSafe();
        analyzedFilesCount = files.length;
      });

      expect(completedJob.status).toBe('COMPLETED');
      expect(completedJob.progressPercentage).toBe(100);
      expect(completedJob.traceId).toBe(job.traceId);
      expect(analyzedFilesCount).toBeGreaterThanOrEqual(4);
      expect(events).toContain('ACQUIRING');
      expect(events).toContain('SANDBOXING');
      expect(events).toContain('ANALYZING');
      expect(events).toContain('COMPLETED');
      expect(logEntries.some((entry) => entry.event === 'job:status_changed')).toBe(true);
      expect(logEntries.some((entry) => entry.traceId === job.traceId)).toBe(true);
    });

    it('supports staged pipeline execution with explicit stage history', async () => {
      const coordinator = new ScanJobCoordinator();
      const job = coordinator.createJob({
        tenantId: 'tenant-stage-01',
        source: {
          type: 'LOCAL_DIRECTORY',
          path: path.resolve('fixtures/001-ssrf-iam-s3'),
        },
      });

      const executedStages: string[] = [];
      const completedJob = await coordinator.executeScanPipeline(job.id, [
        {
          name: 'DISCOVERING',
          async run(_job, ws) {
            executedStages.push('DISCOVERING');
            expect((await ws.listFilesSafe()).length).toBeGreaterThan(0);
          },
        },
        {
          name: 'ANALYZING',
          async run(_job, _ws) {
            executedStages.push('ANALYZING');
          },
        },
      ]);

      expect(completedJob.status).toBe('COMPLETED');
      expect(completedJob.stages).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ name: 'ACQUIRING' }),
          expect.objectContaining({ name: 'SANDBOXING' }),
          expect.objectContaining({ name: 'DISCOVERING' }),
          expect.objectContaining({ name: 'ANALYZING' }),
          expect.objectContaining({ name: 'COMPLETED' }),
        ])
      );
      expect(executedStages).toEqual(['DISCOVERING', 'ANALYZING']);
    });

    it('persists scan jobs and graph snapshots to disk for durable recovery', async () => {
      const storageDir = path.resolve('.tmp-scan-repo-test');
      const repo = new ScanJobRepository({ storageDir });
      const job = repo.createJob({
        tenantId: 'tenant-persist-01',
        source: {
          type: 'LOCAL_DIRECTORY',
          path: path.resolve('fixtures/001-ssrf-iam-s3'),
        },
      });

      const snapshot = {
        tenantId: 'tenant-persist-01',
        version: '1.0.0',
        timestamp: new Date().toISOString(),
        nodes: [{ asset: { id: 'asset-1', tenantId: 'tenant-persist-01', type: 'SERVICE', name: 'svc', environment: 'production', isPublic: false, isSensitiveData: false, criticality: 'MEDIUM', metadata: {}, tags: [] }, findings: [] }],
        edges: [],
      };

      repo.saveJob(job);
      repo.saveGraphSnapshot(job.id, snapshot);

      const loaded = repo.getJob(job.id);
      const loadedSnapshot = repo.getGraphSnapshot(job.id);

      expect(loaded).toBeDefined();
      expect(loaded?.traceId).toBe(job.traceId);
      expect(loadedSnapshot).toEqual(snapshot);

      await fs.rm(storageDir, { recursive: true, force: true });
    });

    it('retries transient failures and drains the queue successfully', async () => {
      const queue = new ScanJobQueue({ concurrency: 1, maxRetries: 2, retryDelayMs: 0 });
      const job = {
        id: 'scan-queue-1',
        tenantId: 'tenant-q-01',
        traceId: 'trace-queue-1',
        source: {
          type: 'LOCAL_DIRECTORY',
          path: path.resolve('fixtures/001-ssrf-iam-s3'),
        },
        status: 'QUEUED',
        createdAt: new Date().toISOString(),
        progressPercentage: 0,
        metadata: {},
        stages: [],
      } as const;

      let attempts = 0;
      await queue.enqueue(job, async () => {
        attempts += 1;
        if (attempts < 2) {
          throw new Error('temporary queue failure');
        }
      });

      await queue.start();
      await queue.waitForIdle();

      expect(attempts).toBe(2);
      expect(queue.getJobStatus(job.id)).toBe('COMPLETED');
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

    it('records lifecycle metrics and terminal durations without double counting', async () => {
      const coordinator = new ScanJobCoordinator();
      const metrics = new ScanJobMetrics();
      const detach = metrics.attach(coordinator);
      const job = coordinator.createJob({
        tenantId: 'tenant-metrics-01',
        source: {
          type: 'LOCAL_DIRECTORY',
          path: path.resolve('fixtures/001-ssrf-iam-s3'),
        },
      });

      await coordinator.executeScan(job.id);
      const snapshot = metrics.snapshot();

      expect(snapshot.created).toBe(1);
      expect(snapshot.completed).toBe(1);
      expect(snapshot.failed).toBe(0);
      expect(snapshot.active).toBe(0);
      expect(snapshot.terminal).toBe(1);
      expect(snapshot.successRate).toBe(1);
      expect(snapshot.averageDurationMs).toBeGreaterThanOrEqual(0);

      coordinator.updateJobStatus(job.id, 'COMPLETED', 100);
      expect(metrics.snapshot().completed).toBe(1);
      detach();
    });

    it('exports metrics in Prometheus format for external observability sinks', async () => {
      const coordinator = new ScanJobCoordinator();
      const metrics = new ScanJobMetrics();
      const detach = metrics.attach(coordinator);
      const job = coordinator.createJob({
        tenantId: 'tenant-metrics-02',
        source: {
          type: 'LOCAL_DIRECTORY',
          path: path.resolve('fixtures/001-ssrf-iam-s3'),
        },
      });

      await coordinator.executeScan(job.id);
      const exported = metrics.toPrometheus();

      expect(exported).toContain('# HELP scan_jobs_created Total scan jobs created');
      expect(exported).toContain('scan_jobs_created 1');
      expect(exported).toContain('# HELP scan_jobs_completed Total completed scan jobs');
      expect(exported).toContain('scan_jobs_completed 1');
      expect(exported).toContain('scan_jobs_success_rate');
      detach();
    });
  });
});
