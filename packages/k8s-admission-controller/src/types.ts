import { z } from 'zod';

export const AdmissionOperationSchema = z.enum(['CREATE', 'UPDATE', 'DELETE', 'CONNECT']);
export type AdmissionOperation = z.infer<typeof AdmissionOperationSchema>;

export interface AdmissionRequest {
  uid: string;
  kind: {
    group: string;
    version: string;
    kind: string;
  };
  resource: {
    group: string;
    version: string;
    resource: string;
  };
  subResource?: string;
  name?: string;
  namespace?: string;
  operation: AdmissionOperation;
  userInfo: {
    username: string;
    uid?: string;
    groups?: string[];
  };
  object?: Record<string, unknown>;
  oldObject?: Record<string, unknown>;
  dryRun?: boolean;
}

export interface AdmissionResponse {
  uid: string;
  allowed: boolean;
  status?: {
    code?: number;
    message?: string;
    reason?: string;
  };
  warnings?: string[];
}

export interface AdmissionReview {
  apiVersion: 'admission.k8s.io/v1';
  kind: 'AdmissionReview';
  request?: AdmissionRequest;
  response?: AdmissionResponse;
}

export interface AdmissionPolicyRule {
  id: string;
  name: string;
  description: string;
  evaluate: (req: AdmissionRequest) => { passed: boolean; reason?: string };
}

export interface AdmissionControllerConfig {
  mode: 'dry-run' | 'enforce'; // Default: 'dry-run'
  failurePolicy: 'Ignore' | 'Fail'; // Default: 'Ignore' (fail-open)
  timeoutMs: number; // Default: 150ms
  port?: number;
  tenantId: string;
}

export interface EvaluationOutcome {
  allowed: boolean;
  violations: string[];
  durationMs: number;
  mode: 'dry-run' | 'enforce';
  decisionType: 'ALLOW' | 'DENY' | 'DRY_RUN_DENY' | 'TIMEOUT_FAIL_OPEN';
}
