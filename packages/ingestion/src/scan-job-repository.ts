import * as fs from 'node:fs';
import * as path from 'node:path';
import type { ScanJob } from './types.js';

export interface ScanJobRepositoryOptions {
  storageDir?: string;
}

export class ScanJobRepository {
  private readonly storageDir: string;

  constructor(options: ScanJobRepositoryOptions = {}) {
    this.storageDir = options.storageDir ?? path.resolve('.scan-job-store');
  }

  public ensureReady(): void {
    fs.mkdirSync(this.storageDir, { recursive: true });
    fs.mkdirSync(path.join(this.storageDir, 'snapshots'), { recursive: true });
  }

  public createJob(params: { tenantId: string; source: ScanJob['source']; metadata?: Record<string, unknown> }): ScanJob {
    const traceId = `scan-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
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

    this.saveJob(job);
    return job;
  }

  public listJobs(): ScanJob[] {
    this.ensureReady();
    const files = fs.readdirSync(this.storageDir)
      .filter((file) => file.endsWith('.json'))
      .filter((file) => file !== 'index.json');

    return files
      .map((file) => {
        try {
          return JSON.parse(fs.readFileSync(path.join(this.storageDir, file), 'utf8')) as ScanJob;
        } catch {
          return undefined;
        }
      })
      .filter((job): job is ScanJob => Boolean(job));
  }

  public saveJob(job: ScanJob): void {
    this.ensureReady();
    const filePath = path.join(this.storageDir, `${job.id}.json`);
    fs.writeFileSync(filePath, JSON.stringify(job, null, 2), 'utf8');
  }

  public getJob(jobId: string): ScanJob | undefined {
    this.ensureReady();
    const filePath = path.join(this.storageDir, `${jobId}.json`);

    try {
      const raw = fs.readFileSync(filePath, 'utf8');
      return JSON.parse(raw) as ScanJob;
    } catch {
      return undefined;
    }
  }

  public saveGraphSnapshot(jobId: string, snapshot: unknown): void {
    this.ensureReady();
    const snapshotDir = path.join(this.storageDir, 'snapshots');
    const filePath = path.join(snapshotDir, `${jobId}.snapshot.json`);
    fs.writeFileSync(filePath, JSON.stringify(snapshot, null, 2), 'utf8');
  }

  public getGraphSnapshot(jobId: string): unknown | undefined {
    this.ensureReady();
    const filePath = path.join(this.storageDir, 'snapshots', `${jobId}.snapshot.json`);

    try {
      const raw = fs.readFileSync(filePath, 'utf8');
      return JSON.parse(raw);
    } catch {
      return undefined;
    }
  }
}
