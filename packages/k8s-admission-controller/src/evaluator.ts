import { WormAuditLogger, type SecurityContext } from '@ai-security-architect/enterprise';
import type {
  AdmissionControllerConfig,
  AdmissionPolicyRule,
  AdmissionRequest,
  EvaluationOutcome,
} from './types.js';

export class AdmissionEvaluator {
  private rules: AdmissionPolicyRule[] = [];
  private auditLogger: WormAuditLogger;
  private config: AdmissionControllerConfig;

  constructor(
    config: AdmissionControllerConfig,
    auditLogger?: WormAuditLogger,
    customRules?: AdmissionPolicyRule[]
  ) {
    this.config = {
      mode: config.mode ?? 'dry-run',
      failurePolicy: config.failurePolicy ?? 'Ignore',
      timeoutMs: config.timeoutMs ?? 150,
      tenantId: config.tenantId ?? 'default-tenant',
    };
    this.auditLogger = auditLogger ?? new WormAuditLogger();
    this.rules = customRules ?? this.getDefaultRules();
  }

  public async evaluate(request: AdmissionRequest): Promise<EvaluationOutcome> {
    const startTime = performance.now();
    const violations: string[] = [];

    // Timeout circuit breaker
    let isTimedOut = false;
    const timeoutHandle = setTimeout(() => {
      isTimedOut = true;
    }, this.config.timeoutMs);

    try {
      for (const rule of this.rules) {
        if (isTimedOut || performance.now() - startTime >= this.config.timeoutMs) {
          isTimedOut = true;
          break;
        }
        const result = rule.evaluate(request);
        if (!result.passed && result.reason) {
          violations.push(`[${rule.id}] ${result.reason}`);
        }
        if (performance.now() - startTime >= this.config.timeoutMs) {
          isTimedOut = true;
          break;
        }
      }
    } finally {
      clearTimeout(timeoutHandle);
    }

    const durationMs = Number((performance.now() - startTime).toFixed(2));
    if (durationMs >= this.config.timeoutMs) {
      isTimedOut = true;
    }

    // Handle timeout scenario
    if (isTimedOut) {
      const decisionType = this.config.failurePolicy === 'Fail' ? 'DENY' : 'TIMEOUT_FAIL_OPEN';
      const allowed = decisionType === 'TIMEOUT_FAIL_OPEN';

      const secCtx: SecurityContext = {
        tenantId: this.config.tenantId,
        userId: request.userInfo?.username ?? 'kube-apiserver',
        userRole: 'SECURITY_ADMIN',
        permissions: ['audit:read', 'audit:verify'],
        scopes: ['*'],
      };

      this.auditLogger.log(
        secCtx,
        'K8S_ADMISSION_TIMEOUT',
        `${request.namespace ?? 'cluster'}/${request.name ?? request.uid}`,
        {
          uid: request.uid,
          operation: request.operation,
          kind: request.kind,
          durationMs,
          timeoutMs: this.config.timeoutMs,
          failurePolicy: this.config.failurePolicy,
          allowed,
        }
      );

      return {
        allowed,
        violations: [`Evaluation timed out after ${durationMs}ms (threshold: ${this.config.timeoutMs}ms)`],
        durationMs,
        mode: this.config.mode,
        decisionType,
      };
    }

    // Determine allow / deny based on mode
    const hasViolations = violations.length > 0;
    let allowed = true;
    let decisionType: EvaluationOutcome['decisionType'] = 'ALLOW';

    if (hasViolations) {
      if (this.config.mode === 'enforce') {
        allowed = false;
        decisionType = 'DENY';
      } else {
        // dry-run mode: allow deployment through, but record dry-run violation
        allowed = true;
        decisionType = 'DRY_RUN_DENY';
      }
    }

    // Write complete WORM audit log entry
    const secCtx: SecurityContext = {
      tenantId: this.config.tenantId,
      userId: request.userInfo?.username ?? 'kube-apiserver',
      userRole: 'SECURITY_ADMIN',
      permissions: ['audit:read', 'audit:verify'],
      scopes: ['*'],
    };

    this.auditLogger.log(
      secCtx,
      `K8S_ADMISSION_${decisionType}`,
      `${request.namespace ?? 'cluster'}/${request.name ?? request.uid}`,
      {
        uid: request.uid,
        operation: request.operation,
        kind: request.kind,
        mode: this.config.mode,
        allowed,
        violations,
        durationMs,
      }
    );

    return {
      allowed,
      violations,
      durationMs,
      mode: this.config.mode,
      decisionType,
    };
  }

  private getDefaultRules(): AdmissionPolicyRule[] {
    return [
      {
        id: 'SEC-K8S-001',
        name: 'Disallow Privileged Containers',
        description: 'Blocks containers running with privileged securityContext',
        evaluate: (req) => {
          const spec = (req.object?.spec as any) ?? {};
          const containers = [
            ...(spec.containers || []),
            ...(spec.initContainers || []),
            ...(spec.template?.spec?.containers || []),
            ...(spec.template?.spec?.initContainers || []),
          ];

          for (const c of containers) {
            if (c.securityContext?.privileged === true) {
              return {
                passed: false,
                reason: `Container '${c.name}' has securityContext.privileged=true. Privileged execution is forbidden.`,
              };
            }
          }
          return { passed: true };
        },
      },
      {
        id: 'SEC-K8S-002',
        name: 'Disallow Floating Base Image Tags',
        description: 'Requires container images to have immutable tags or digests',
        evaluate: (req) => {
          const spec = (req.object?.spec as any) ?? {};
          const containers = [
            ...(spec.containers || []),
            ...(spec.initContainers || []),
            ...(spec.template?.spec?.containers || []),
            ...(spec.template?.spec?.initContainers || []),
          ];

          for (const c of containers) {
            const img = String(c.image || '');
            if (!img) continue;
            if (img.endsWith(':latest') || (!img.includes(':') && !img.includes('@'))) {
              return {
                passed: false,
                reason: `Container '${c.name}' uses floating image tag '${img}'. Pinned tags or SHA256 digests required.`,
              };
            }
          }
          return { passed: true };
        },
      },
      {
        id: 'SEC-K8S-003',
        name: 'Disallow Wildcard ClusterRoles',
        description: 'Blocks ClusterRole resources with wildcard verbs, resources, or apiGroups',
        evaluate: (req) => {
          if (req.kind.kind !== 'ClusterRole') return { passed: true };
          const rules = (req.object?.rules as any[]) || [];
          for (const rule of rules) {
            const hasWildcardGroup = rule.apiGroups?.includes('*');
            const hasWildcardResource = rule.resources?.includes('*');
            const hasWildcardVerb = rule.verbs?.includes('*');

            if (hasWildcardGroup && hasWildcardResource && hasWildcardVerb) {
              return {
                passed: false,
                reason: 'ClusterRole grants administrative wildcard privileges (* on *:*). Least privilege required.',
              };
            }
          }
          return { passed: true };
        },
      },
    ];
  }
}
