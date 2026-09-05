import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto';
import type {
  ScanJob,
  ScanJobStatus,
  RepositorySource,
  EphemeralWorkspace,
  ScanJobPipelineStage,
  ScanJobStageEntry,
  ScanJobLogEntry,
} from './types.js';
import { ScanJobRepository } from './scan-job-repository.js';
import { WorkspaceManager } from './workspace-manager.js';
import { RepositoryAcquisitionManager } from './repository-acquirer.js';

export interface ScanJobCoordinatorOptions {
  workspaceManager?: WorkspaceManager;
  acquisitionManager?: RepositoryAcquisitionManager;
  repository?: ScanJobRepository;
}

export type ScanJobPipelineHook = (job: ScanJob, workspace: EphemeralWorkspace) => Promise<void>;

export class ScanJobCoordinator extends EventEmitter {
  private readonly jobs = new Map<string, ScanJob>();
  private readonly workspaces = new Map<string, EphemeralWorkspace>();
  private readonly workspaceManager: WorkspaceManager;
  private readonly acquisitionManager: RepositoryAcquisitionManager;
  private readonly repository: ScanJobRepository;

  constructor(options: ScanJobCoordinatorOptions = {}) {
    super();
    this.workspaceManager = options.workspaceManager ?? new WorkspaceManager();
    this.acquisitionManager = options.acquisitionManager ?? new RepositoryAcquisitionManager();
    this.repository = options.repository ?? new ScanJobRepository();
  }

  public createJob(params: { tenantId: string; source: RepositorySource; metadata?: Record<string, unknown> }): ScanJob {
    const traceId = `scan-${randomUUID()}`;
    const job: ScanJob = {
      id: traceId,
      tenantId: params.tenantId,
      traceId,
      source: params.source,
      status: 'QUEUED',
      createdAt: new Date().toISOString(),
      progressPercentage: 0,
      metadata: params.metadata ?? {},
      stages: [
        {
          name: 'QUEUED',
          startedAt: new Date().toISOString(),
          status: 'QUEUED',
          metadata: {},
        },
      ],
    };

    this.jobs.set(job.id, job);
    this.repository.saveJob(job);
    this.emit('job:created', job);
    this.emit('job:log', this.createLogEntry('job:created', job, {
      message: `Scan job created for tenant ${job.tenantId}`,
      details: { source: job.source },
    }));
    return job;
  }

  public getJob(jobId: string): ScanJob | undefined {
    return this.jobs.get(jobId);
  }

  public restoreJobs(): ScanJob[] {
    const jobs = this.repository.listJobs();
    for (const job of jobs) {
      this.jobs.set(job.id, job);
    }
    return Array.from(this.jobs.values());
  }

  public listJobs(tenantId?: string): ScanJob[] {
    const all = Array.from(this.jobs.values());
    return tenantId ? all.filter((j) => j.tenantId === tenantId) : all;
  }

  public updateJobStatus(
    jobId: string,
    status: ScanJobStatus,
    progressPercentage?: number,
    error?: string
  ): ScanJob {
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

    const stageIndex = job.stages.findIndex((stage) => stage.name === status);
    const stageEntry: ScanJobStageEntry = {
      name: status,
      startedAt: this.getStageStartedAt(job, status),
      completedAt: new Date().toISOString(),
      status,
      error,
      metadata: {},
    };

    if (stageIndex >= 0) {
      job.stages[stageIndex] = stageEntry;
    } else {
      job.stages.push(stageEntry);
    }

    this.emit('job:status_changed', job);
    this.repository.saveJob(job);
    this.emit('job:log', this.createLogEntry('job:status_changed', job, {
      message: `Scan job moved to ${status} state`,
      details: {
        progressPercentage: job.progressPercentage,
        error,
      },
    }));
    return job;
  }

  public async executeScan(jobId: string, pipelineHook?: ScanJobPipelineHook): Promise<ScanJob> {
    const stages: ScanJobPipelineStage[] = pipelineHook
      ? [{ name: 'ANALYZING', run: async (job, workspace) => pipelineHook(job, workspace) }]
      : [];

    return this.executeScanPipeline(jobId, stages);
  }

  public async executeScanPipeline(
    jobId: string,
    stages: ScanJobPipelineStage[] = []
  ): Promise<ScanJob> {
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

      for (let index = 0; index < stages.length; index++) {
        const stage = stages[index];
        const progress = Math.round(((index + 1) / Math.max(1, stages.length + 1)) * 100);
        this.updateJobStatus(jobId, stage.name, progress);
        await stage.run(job, workspace);
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

  private getStageStartedAt(job: ScanJob, status: ScanJobStatus): string {
    const existingStage = job.stages.find((stage) => stage.name === status);
    return existingStage?.startedAt ?? new Date().toISOString();
  }

  private createLogEntry(
    event: string,
    job: ScanJob,
    params: { message: string; details?: Record<string, unknown> }
  ): ScanJobLogEntry {
    return {
      event,
      traceId: job.traceId,
      tenantId: job.tenantId,
      status: job.status,
      timestamp: new Date().toISOString(),
      message: params.message,
      details: params.details ?? {},
    };
  }
}
