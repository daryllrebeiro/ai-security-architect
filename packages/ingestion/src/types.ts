import { z } from 'zod';

export const ScanJobStatusSchema = z.enum([
  'QUEUED',
  'ACQUIRING',
  'SANDBOXING',
  'DISCOVERING',
  'ANALYZING',
  'BUILDING_GRAPH',
  'COMPLETED',
  'FAILED',
  'CANCELLED',
]);

export type ScanJobStatus = z.infer<typeof ScanJobStatusSchema>;

export const LocalDirectorySourceSchema = z.object({
  type: z.literal('LOCAL_DIRECTORY'),
  path: z.string().min(1),
});

export const GitRemoteSourceSchema = z.object({
  type: z.literal('GIT_REMOTE'),
  url: z.string().min(1),
  branch: z.string().default('main'),
  commitSha: z.string().optional(),
});

export const RepositorySourceSchema = z.discriminatedUnion('type', [
  LocalDirectorySourceSchema,
  GitRemoteSourceSchema,
]);

export type RepositorySource = z.infer<typeof RepositorySourceSchema>;

export const ScanJobSchema = z.object({
  id: z.string().min(1),
  tenantId: z.string().min(1),
  source: RepositorySourceSchema,
  status: ScanJobStatusSchema.default('QUEUED'),
  createdAt: z.string().datetime(),
  startedAt: z.string().datetime().optional(),
  completedAt: z.string().datetime().optional(),
  error: z.string().optional(),
  progressPercentage: z.number().min(0).max(100).default(0),
  metadata: z.record(z.unknown()).default({}),
});

export type ScanJob = z.infer<typeof ScanJobSchema>;

export interface SandboxExecutionOptions {
  timeoutMs?: number;
  maxBufferSizeBytes?: number;
  env?: Record<string, string>;
  allowNetwork?: boolean;
}

export interface SandboxExecutionResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  durationMs: number;
  timedOut: boolean;
}

export interface EphemeralWorkspace {
  id: string;
  workspaceDir: string;
  resolveSafePath(relativePath: string): string;
  readSafeFile(relativePath: string): Promise<string>;
  listFilesSafe(subDir?: string): Promise<string[]>;
  cleanup(): Promise<void>;
}
