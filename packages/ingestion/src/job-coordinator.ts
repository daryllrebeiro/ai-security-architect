import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto';
import type { ScanJob, ScanJobStatus, RepositorySource, EphemeralWorkspace } from './types.js';
import { WorkspaceManager } from './workspace-manager.js';
import { RepositoryAcquisitionManager } from './repository-acquirer.js';

export interface ScanJobCoordinatorOptions {
  workspaceManager?: WorkspaceManager;
  acquisitionManager?: RepositoryAcquisitionManager;
}

export type ScanJobPipelineHook = (job: ScanJob, workspace: EphemeralWorkspace) => Promise<void>;

export class ScanJobCoordinator extends EventEmitter {
  private readonly jobs = new Map<string, ScanJob>();
  private readonly workspaces = new Map<string, EphemeralWorkspace>();
  private readonly workspaceManager: WorkspaceManager;
  private readonly acquisitionManager: RepositoryAcquisitionManager;

  constructor(options: ScanJobCoordinatorOptions = {}) {
    super();
    this.workspaceManager = options.workspaceManager ?? new WorkspaceManager();
    this.acquisitionManager = options.acquisitionManager ?? new RepositoryAcquisitionManager();
  }

  public createJob(params: { tenantId: string; source: RepositorySource; metadata?: Record<string, unknown> }): ScanJob {
    const job: ScanJob = {
      id: `scan-${randomUUID()}`,
      tenantId: params.tenantId,
      source: params.source,
      status: 'QUEUED',
      createdAt: new Date().toISOString(),
      progressPercentage: 0,
      metadata: params.metadata ?? {},
    };

    this.jobs.set(job.id, job);
    this.emit('job:created', job);
    return job;
  }

  public getJob(jobId: string): ScanJob | undefined {
    return this.jobs.get(jobId);
  }

  public listJobs(tenantId?: string): ScanJob[] {
    const all = Array.from(this.jobs.values());
    return tenantId ? all.filter((j) => j.tenantId === tenantId) : all;
  }

  public updateJobStatus(jobId: string, status: ScanJobStatus, progressPercentage?: number, error?: string): ScanJob {
    const job = this.jobs.get(jobId);
    if (!job) {
      throw new Error(`Job "${jobId}" not found`);
    }

    job.status = status;
    if (progressPercentage !== undefined) {
      job.progressPercentage = progressPercentage;
    }
    if (error !== undefined) {
      job.error = error;
    }

    if (status === 'ACQUIRING' && !job.startedAt) {
      job.startedAt = new Date().toISOString();
    }

    if (['COMPLETED', 'FAILED', 'CANCELLED'].includes(status) && !job.completedAt) {
      job.completedAt = new Date().toISOString();
    }

    this.emit('job:status_changed', job);
    return job;
  }

  public async executeScan(jobId: string, pipelineHook?: ScanJobPipelineHook): Promise<ScanJob> {
    const job = this.jobs.get(jobId);
    if (!job) {
      throw new Error(`Job "${jobId}" not found`);
    }

    let workspace: EphemeralWorkspace | undefined;

    try {
      this.updateJobStatus(jobId, 'ACQUIRING', 10);
      workspace = await this.workspaceManager.createWorkspace();
      this.workspaces.set(jobId, workspace);

      await this.acquisitionManager.acquire(job.source, workspace);
      this.updateJobStatus(jobId, 'SANDBOXING', 30);

      if (pipelineHook) {
        this.updateJobStatus(jobId, 'ANALYZING', 50);
        await pipelineHook(job, workspace);
      }

      this.updateJobStatus(jobId, 'COMPLETED', 100);
    } catch (err: unknown) {
      const errorMsg = (err as Error).message;
      this.updateJobStatus(jobId, 'FAILED', job.progressPercentage, errorMsg);
    } finally {
      if (workspace) {
        await workspace.cleanup();
        this.workspaces.delete(jobId);
      }
    }

    return this.jobs.get(jobId)!;
  }
}
