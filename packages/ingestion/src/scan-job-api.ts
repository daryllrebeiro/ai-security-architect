import {
  RepositorySourceSchema,
  type RepositorySource,
  type ScanJob,
} from './types.js';
import { ScanJobCoordinator } from './job-coordinator.js';
import { ScanJobMetrics } from './scan-job-metrics.js';

export interface ScanJobApiRequest {
  method: string;
  path: string;
  query?: Record<string, string | undefined>;
  body?: unknown;
}

export interface ScanJobApiResponse {
  status: number;
  headers: Record<string, string>;
  body: unknown;
}

interface CreateJobBody {
  tenantId: string;
  source: RepositorySource;
  metadata?: Record<string, unknown>;
}

export class ScanJobApi {
  private readonly detachMetrics: () => void;

  constructor(
    private readonly coordinator: ScanJobCoordinator,
    private readonly metrics: ScanJobMetrics
  ) {
    this.detachMetrics = metrics.attach(coordinator);
  }

  public close(): void {
    this.detachMetrics();
  }

  public handle(request: ScanJobApiRequest): ScanJobApiResponse {
    const method = request.method.toUpperCase();
    const path = this.normalizePath(request.path);

    if (method === 'GET' && path === '/health') {
      return this.json(200, { status: 'ok' });
    }

    if (method === 'GET' && path === '/metrics') {
      return {
        status: 200,
        headers: { 'content-type': 'text/plain; version=0.0.4' },
        body: this.metrics.toPrometheus(),
      };
    }

    if (method === 'GET' && path === '/jobs') {
      const tenantId = request.query?.tenantId;
      if (!tenantId) return this.error(400, 'tenantId query parameter is required');
      return this.json(200, this.coordinator.listJobs(tenantId));
    }

    if (method === 'POST' && path === '/jobs') {
      const parsed = this.parseCreateJob(request.body);
      if (!parsed.success) return this.error(400, parsed.error);
      return this.json(201, this.coordinator.createJob(parsed.value));
    }

    const jobId = this.getJobId(path);
    if (method === 'GET' && jobId) {
      const tenantId = request.query?.tenantId;
      if (!tenantId) return this.error(400, 'tenantId query parameter is required');

      const job = this.coordinator.getJob(jobId);
      if (!job || job.tenantId !== tenantId) return this.error(404, 'Job not found');
      return this.json(200, job);
    }

    return this.error(405, 'Method not allowed');
  }

  private parseCreateJob(body: unknown):
    | { success: true; value: CreateJobBody }
    | { success: false; error: string } {
    if (!body || typeof body !== 'object') {
      return { success: false, error: 'Request body must be an object' };
    }

    const candidate = body as Record<string, unknown>;
    if (typeof candidate.tenantId !== 'string' || candidate.tenantId.length === 0) {
      return { success: false, error: 'tenantId is required' };
    }

    const source = RepositorySourceSchema.safeParse(candidate.source);
    if (!source.success) return { success: false, error: 'A valid source is required' };

    if (candidate.metadata !== undefined && (
      typeof candidate.metadata !== 'object' || candidate.metadata === null || Array.isArray(candidate.metadata)
    )) {
      return { success: false, error: 'metadata must be an object' };
    }

    return {
      success: true,
      value: {
        tenantId: candidate.tenantId,
        source: source.data,
        metadata: candidate.metadata as Record<string, unknown> | undefined,
      },
    };
  }

  private getJobId(path: string): string | undefined {
    const match = /^\/jobs\/([^/]+)$/.exec(path);
    return match ? decodeURIComponent(match[1]) : undefined;
  }

  private normalizePath(path: string): string {
    const withoutQuery = path.split('?')[0];
    if (withoutQuery.length > 1 && withoutQuery.endsWith('/')) {
      return withoutQuery.slice(0, -1);
    }
    return withoutQuery;
  }

  private json(status: number, body: ScanJob | ScanJob[] | { status: string }): ScanJobApiResponse {
    return {
      status,
      headers: { 'content-type': 'application/json; charset=utf-8' },
      body,
    };
  }

  private error(status: number, message: string): ScanJobApiResponse {
    return this.json(status, { error: message });
  }
}