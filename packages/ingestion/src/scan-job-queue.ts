import type { ScanJob, ScanJobStageEntry, ScanJobStatus } from './types.js';

export interface ScanJobQueueOptions {
  concurrency?: number;
  maxRetries?: number;
  retryDelayMs?: number;
}

export type QueueJobHandler = () => Promise<void> | void;

export type QueueJobStatus = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED';

export type QueuedScanJob = Omit<ScanJob, 'status' | 'stages'> & {
  attempts: number;
  lastError?: string;
  status: QueueJobStatus;
  stages: readonly ScanJobStageEntry[];
};

export type QueueInputJob = Omit<ScanJob, 'status' | 'stages'> & {
  status: ScanJobStatus;
  stages: readonly ScanJobStageEntry[];
};

export class ScanJobQueue {
  private queue: Array<{ job: QueuedScanJob; handler: QueueJobHandler }> = [];
  private readonly running = new Set<string>();
  private readonly maxRetries: number;
  private readonly retryDelayMs: number;
  private readonly concurrency: number;
  private idleResolve?: () => void;
  private idlePromise?: Promise<void>;

  constructor(options: ScanJobQueueOptions = {}) {
    this.concurrency = options.concurrency ?? 1;
    this.maxRetries = options.maxRetries ?? 2;
    this.retryDelayMs = options.retryDelayMs ?? 50;
  }

  public enqueue(job: QueueInputJob, handler: QueueJobHandler): Promise<void> {
    const queuedJob: QueuedScanJob = {
      ...job,
      attempts: 0,
      status: 'QUEUED',
    };

    this.queue.push({ job: queuedJob, handler });
    return Promise.resolve();
  }

  public async start(): Promise<void> {
    while (this.queue.length > 0 || this.running.size > 0) {
      while (this.queue.length > 0 && this.running.size < this.concurrency) {
        const next = this.queue.shift();
        if (!next) {
          break;
        }

        this.running.add(next.job.id);
        next.job.status = 'RUNNING';

        void this.run(next).finally(() => {
          this.running.delete(next.job.id);
          if (this.queue.length === 0 && this.running.size === 0) {
            this.resolveIdle();
          }
        });
      }

      if (this.queue.length === 0 && this.running.size === 0) {
        break;
      }

      await this.delay(10);
    }

    if (this.queue.length === 0 && this.running.size === 0) {
      this.resolveIdle();
    }
  }

  public async waitForIdle(): Promise<void> {
    if (this.queue.length === 0 && this.running.size === 0) {
      return;
    }

    if (!this.idlePromise) {
      this.idlePromise = new Promise<void>((resolve) => {
        this.idleResolve = resolve;
      });
    }

    return this.idlePromise;
  }

  public getJobStatus(jobId: string): string {
    const queued = this.queue.find((entry) => entry.job.id === jobId);
    if (queued) {
      return queued.job.status;
    }

    for (const entry of this.queue) {
      if (entry.job.id === jobId) {
        return entry.job.status;
      }
    }

    return 'COMPLETED';
  }

  private async run(entry: { job: QueuedScanJob; handler: QueueJobHandler }): Promise<void> {
    const { job, handler } = entry;

    try {
      job.attempts += 1;
      await handler();
      job.status = 'COMPLETED';
      this.queue = this.queue.filter((item) => item.job.id !== job.id);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      job.lastError = message;

      if (job.attempts <= this.maxRetries) {
        job.status = 'QUEUED';
        await this.delay(this.retryDelayMs);
        this.queue.push({ job, handler });
        return;
      }

      job.status = 'FAILED';
    }
  }

  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  private resolveIdle(): void {
    if (this.idleResolve) {
      const resolve = this.idleResolve;
      this.idleResolve = undefined;
      this.idlePromise = undefined;
      resolve();
    }
  }
}
