import type { EventEmitter } from 'node:events';
import type { ScanJob, ScanJobStatus } from './types.js';

export interface ScanJobMetricsSnapshot {
  created: number;
  completed: number;
  failed: number;
  cancelled: number;
  active: number;
  terminal: number;
  successRate: number;
  averageDurationMs: number;
}

type CoordinatorEvents = EventEmitter & {
  on(event: 'job:created' | 'job:status_changed', listener: (job: ScanJob) => void): CoordinatorEvents;
  off(event: 'job:created' | 'job:status_changed', listener: (job: ScanJob) => void): CoordinatorEvents;
};

export class ScanJobMetrics {
  private readonly terminalJobs = new Set<string>();
  private readonly durationsMs: number[] = [];
  private created = 0;
  private completed = 0;
  private failed = 0;
  private cancelled = 0;
  private active = 0;
  private coordinator?: CoordinatorEvents;

  public toPrometheus(): string {
    const snapshot = this.snapshot();
    const lines = [
      '# HELP scan_jobs_created Total scan jobs created',
      `scan_jobs_created ${snapshot.created}`,
      '# HELP scan_jobs_completed Total completed scan jobs',
      `scan_jobs_completed ${snapshot.completed}`,
      '# HELP scan_jobs_failed Total failed scan jobs',
      `scan_jobs_failed ${snapshot.failed}`,
      '# HELP scan_jobs_cancelled Total cancelled scan jobs',
      `scan_jobs_cancelled ${snapshot.cancelled}`,
      '# HELP scan_jobs_active Number of jobs currently active',
      `scan_jobs_active ${snapshot.active}`,
      '# HELP scan_jobs_success_rate Success rate for terminal jobs',
      `scan_jobs_success_rate ${snapshot.successRate}`,
      '# HELP scan_jobs_average_duration_ms Average scan job duration in milliseconds',
      `scan_jobs_average_duration_ms ${snapshot.averageDurationMs}`,
    ];

    return lines.join('\n');
  }

  private readonly onCreated = (job: ScanJob): void => {
    this.created += 1;
    this.active += 1;
    this.observeStatus(job);
  };

  private readonly onStatusChanged = (job: ScanJob): void => {
    this.observeStatus(job);
  };

  public attach(coordinator: CoordinatorEvents): () => void {
    this.detach();
    this.coordinator = coordinator;
    coordinator.on('job:created', this.onCreated);
    coordinator.on('job:status_changed', this.onStatusChanged);
    return () => this.detach();
  }

  public detach(): void {
    if (!this.coordinator) return;
    this.coordinator.off('job:created', this.onCreated);
    this.coordinator.off('job:status_changed', this.onStatusChanged);
    this.coordinator = undefined;
  }

  public snapshot(): ScanJobMetricsSnapshot {
    const terminal = this.completed + this.failed + this.cancelled;
    return {
      created: this.created,
      completed: this.completed,
      failed: this.failed,
      cancelled: this.cancelled,
      active: this.active,
      terminal,
      successRate: terminal === 0 ? 0 : this.completed / terminal,
      averageDurationMs: this.durationsMs.length === 0
        ? 0
        : this.durationsMs.reduce((total, duration) => total + duration, 0) / this.durationsMs.length,
    };
  }

  private observeStatus(job: ScanJob): void {
    const terminalStatuses: ScanJobStatus[] = ['COMPLETED', 'FAILED', 'CANCELLED'];
    if (!terminalStatuses.includes(job.status) || this.terminalJobs.has(job.id)) return;

    this.terminalJobs.add(job.id);
    this.active = Math.max(0, this.active - 1);
    if (job.status === 'COMPLETED') this.completed += 1;
    if (job.status === 'FAILED') this.failed += 1;
    if (job.status === 'CANCELLED') this.cancelled += 1;

    if (job.startedAt && job.completedAt) {
      const durationMs = Date.parse(job.completedAt) - Date.parse(job.startedAt);
      if (Number.isFinite(durationMs) && durationMs >= 0) this.durationsMs.push(durationMs);
    }
  }
}