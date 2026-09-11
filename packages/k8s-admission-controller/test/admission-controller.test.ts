import { describe, it, expect } from 'vitest';
import { WormAuditLogger } from '@ai-security-architect/enterprise';
import {
  AdmissionEvaluator,
  AdmissionServer,
  type AdmissionRequest,
  type AdmissionReview,
} from '../src/index.js';

describe('Task E.3 — Kubernetes Admission Controller (Live Enforcement)', () => {
  const violatingPodRequest: AdmissionRequest = {
    uid: 'req-pod-violating-001',
    kind: { group: '', version: 'v1', kind: 'Pod' },
    resource: { group: '', version: 'v1', resource: 'pods' },
    operation: 'CREATE',
    name: 'privileged-debug-pod',
    namespace: 'production',
    userInfo: { username: 'deployer-sa@corp.internal' },
    object: {
      apiVersion: 'v1',
      kind: 'Pod',
      metadata: { name: 'privileged-debug-pod' },
      spec: {
        containers: [
          {
            name: 'main-app',
            image: 'mycorp.azurecr.io/app:v1.2.3',
            securityContext: {
              privileged: true, // Violation of SEC-K8S-001
            },
          },
        ],
      },
    },
  };

  const cleanPodRequest: AdmissionRequest = {
    uid: 'req-pod-clean-002',
    kind: { group: '', version: 'v1', kind: 'Pod' },
    resource: { group: '', version: 'v1', resource: 'pods' },
    operation: 'CREATE',
    name: 'safe-order-pod',
    namespace: 'production',
    userInfo: { username: 'deployer-sa@corp.internal' },
    object: {
      apiVersion: 'v1',
      kind: 'Pod',
      metadata: { name: 'safe-order-pod' },
      spec: {
        containers: [
          {
            name: 'order-api',
            image: 'mycorp.azurecr.io/order-api:v2.0.1',
            securityContext: {
              privileged: false,
            },
          },
        ],
      },
    },
  };

  it('denies budget-violating pod in enforce mode with explanatory message', async () => {
    const auditLogger = new WormAuditLogger();
    const evaluator = new AdmissionEvaluator(
      {
        mode: 'enforce',
        failurePolicy: 'Ignore',
        timeoutMs: 200,
        tenantId: 'tenant-k8s-01',
      },
      auditLogger
    );

    const outcome = await evaluator.evaluate(violatingPodRequest);
    expect(outcome.allowed).toBe(false);
    expect(outcome.decisionType).toBe('DENY');
    expect(outcome.violations).toHaveLength(1);
    expect(outcome.violations[0]).toContain('privileged=true');

    // Test HTTP server handleReview format
    const server = new AdmissionServer(
      { mode: 'enforce', failurePolicy: 'Ignore', timeoutMs: 200, tenantId: 'tenant-k8s-01' },
      evaluator
    );

    const review: AdmissionReview = {
      apiVersion: 'admission.k8s.io/v1',
      kind: 'AdmissionReview',
      request: violatingPodRequest,
    };

    const reviewResponse = await server.handleReview(review);
    expect(reviewResponse.response?.allowed).toBe(false);
    expect(reviewResponse.response?.status?.code).toBe(403);
    expect(reviewResponse.response?.status?.reason).toBe('SecurityBudgetViolation');
    expect(reviewResponse.response?.status?.message).toContain('privileged=true');

    // Verify WORM audit entry
    const entries = auditLogger.getAllEntries();
    expect(entries.length).toBeGreaterThanOrEqual(1);
    const lastEntry = entries[entries.length - 1];
    expect(lastEntry.action).toBe('K8S_ADMISSION_DENY');
    expect(lastEntry.userId).toBe('deployer-sa@corp.internal');
  });

  it('allows budget-violating pod in dry-run mode with warnings and WORM audit logging', async () => {
    const auditLogger = new WormAuditLogger();
    const evaluator = new AdmissionEvaluator(
      {
        mode: 'dry-run',
        failurePolicy: 'Ignore',
        timeoutMs: 200,
        tenantId: 'tenant-k8s-01',
      },
      auditLogger
    );

    const outcome = await evaluator.evaluate(violatingPodRequest);
    expect(outcome.allowed).toBe(true); // Dry-run NEVER blocks!
    expect(outcome.decisionType).toBe('DRY_RUN_DENY');
    expect(outcome.violations.length).toBeGreaterThan(0);

    const server = new AdmissionServer(
      { mode: 'dry-run', failurePolicy: 'Ignore', timeoutMs: 200, tenantId: 'tenant-k8s-01' },
      evaluator
    );

    const reviewResponse = await server.handleReview({
      apiVersion: 'admission.k8s.io/v1',
      kind: 'AdmissionReview',
      request: violatingPodRequest,
    });

    expect(reviewResponse.response?.allowed).toBe(true);
    expect(reviewResponse.response?.warnings).toBeDefined();
    expect(reviewResponse.response?.warnings?.[0]).toContain('[DRY-RUN SECURITY WARNING]');

    // Verify audit log has DRY_RUN_DENY
    const entries = auditLogger.getAllEntries();
    const lastEntry = entries[entries.length - 1];
    expect(lastEntry.action).toBe('K8S_ADMISSION_DRY_RUN_DENY');
  });

  it('allows safe compliant pods without violations or warnings', async () => {
    const evaluator = new AdmissionEvaluator({
      mode: 'enforce',
      failurePolicy: 'Ignore',
      timeoutMs: 200,
      tenantId: 'tenant-k8s-01',
    });

    const outcome = await evaluator.evaluate(cleanPodRequest);
    expect(outcome.allowed).toBe(true);
    expect(outcome.violations).toHaveLength(0);
    expect(outcome.decisionType).toBe('ALLOW');
  });

  it('fails open upon timeout when configured with failurePolicy: Ignore', async () => {
    const auditLogger = new WormAuditLogger();
    // Rule that artificially delays execution
    const slowRule = {
      id: 'SLOW-001',
      name: 'Simulated Slow Rule',
      description: 'Slow evaluation',
      evaluate: () => {
        const start = Date.now();
        while (Date.now() - start < 30) {
          // busy wait 30ms
        }
        return { passed: false, reason: 'Slow violation' };
      },
    };

    const evaluator = new AdmissionEvaluator(
      {
        mode: 'enforce',
        failurePolicy: 'Ignore', // Fail-open
        timeoutMs: 10, // 10ms timeout threshold
        tenantId: 'tenant-k8s-01',
      },
      auditLogger,
      [slowRule]
    );

    const outcome = await evaluator.evaluate(cleanPodRequest);
    expect(outcome.allowed).toBe(true); // Must fail open!
    expect(outcome.decisionType).toBe('TIMEOUT_FAIL_OPEN');
    expect(outcome.violations[0]).toContain('Evaluation timed out');

    // Confirm audit log recorded the timeout
    const entries = auditLogger.getAllEntries();
    expect(entries.some((e) => e.action === 'K8S_ADMISSION_TIMEOUT')).toBe(true);
  });
});
