import { Finding, createEvidence } from '@ai-security-architect/core';

export class DisallowedEndpointError extends Error {
  constructor(endpoint: string) {
    super(
      `SECURITY GUARDRAIL TRIGGERED: Endpoint "${endpoint}" is not in the configured allowedEndpoints allowlist. Probing prohibited.`
    );
    this.name = 'DisallowedEndpointError';
  }
}

export interface LiveValidationConfig {
  enabled: boolean;
  allowedEndpoints: string[];
  timeoutMs?: number;
}

export interface DeclaredGraphExpectation {
  assetId: string;
  tenantId: string;
  endpointUrl: string;
  declaredReachable: boolean;
  declaredRequiresAuth: boolean;
}

export interface ProbeResult {
  endpointUrl: string;
  reachable: boolean;
  httpStatus?: number;
  authRequired: boolean; // true if 401/403 returned on unauthenticated probe
  tlsValid: boolean;
  latencyMs: number;
  error?: string;
}

export class LiveValidator {
  private config: LiveValidationConfig;
  private allowedSet: Set<string>;
  private fetchFn: typeof fetch;

  constructor(config: LiveValidationConfig, customFetch?: typeof fetch) {
    this.config = config;
    this.allowedSet = new Set(config.allowedEndpoints || []);
    this.fetchFn = customFetch || globalThis.fetch;
  }

  isEndpointAllowed(url: string): boolean {
    return this.allowedSet.has(url);
  }

  /**
   * Safe, read-only, non-destructive probe against allowlisted endpoint
   */
  async probeEndpoint(url: string): Promise<ProbeResult> {
    if (!this.config.enabled) {
      throw new Error('Live validation is disabled in configuration.');
    }

    if (!this.isEndpointAllowed(url)) {
      throw new DisallowedEndpointError(url);
    }

    const start = Date.now();
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.config.timeoutMs ?? 5000);

      const res = await this.fetchFn(url, {
        method: 'GET',
        headers: {
          'User-Agent': 'ai-security-architect-live-probe/1.0',
          'Accept': '*/*',
        },
        signal: controller.signal,
      });

      clearTimeout(timeoutId);
      const latencyMs = Date.now() - start;

      // Status 401 or 403 means auth is enforced
      const authRequired = res.status === 401 || res.status === 403;
      const reachable = res.status < 500;

      return {
        endpointUrl: url,
        reachable,
        httpStatus: res.status,
        authRequired,
        tlsValid: url.startsWith('https://'),
        latencyMs,
      };
    } catch (err: any) {
      const latencyMs = Date.now() - start;
      return {
        endpointUrl: url,
        reachable: false,
        authRequired: false,
        tlsValid: false,
        latencyMs,
        error: err?.message || 'Connection failed',
      };
    }
  }

  /**
   * Reconciles live probe results against declared graph expectations and surfaces MODEL_DISAGREEMENT findings.
   */
  reconcile(
    expectations: DeclaredGraphExpectation[],
    probeResults: ProbeResult[]
  ): Finding[] {
    const findings: Finding[] = [];
    const resultMap = new Map<string, ProbeResult>();
    for (const res of probeResults) {
      resultMap.set(res.endpointUrl, res);
    }

    for (const exp of expectations) {
      const probe = resultMap.get(exp.endpointUrl);
      if (!probe) continue;

      // 1. Reachability Disagreement
      if (exp.declaredReachable && !probe.reachable) {
        findings.push({
          id: `finding-disagreement-reachability-${exp.assetId}`,
          tenantId: exp.tenantId,
          assetId: exp.assetId,
          category: 'MODEL_DISAGREEMENT',
          ruleId: 'LIVE-VAL-001',
          title: `Model Disagreement: Declared Reachable Endpoint is Live Unreachable (${exp.endpointUrl})`,
          description: `Graph topology declares this endpoint reachable per IaC configuration, but live empirical probing failed (${probe.error || `HTTP ${probe.httpStatus}`}). Declared State: REACHABLE. Live Observed: UNREACHABLE.`,
          severity: 'MEDIUM',
          confidence: 'CERTAIN',
          scanner: 'live-validation-engine',
          evidence: createEvidence({
            id: `ev-reachability-disagree-${exp.assetId}`,
            tenantId: exp.tenantId,
            sourceType: 'RUNTIME_TRACE',
            repository: 'infrastructure/live',
            filePath: exp.endpointUrl,
            lineStart: 1,
            lineEnd: 1,
            snippet: `Declared expectation: reachable=true. Live probe: reachable=false, error="${probe.error || ''}"`,
            scanner: 'live-validation-engine',
          }),
          remediationRecommendation: 'Investigate live networking, DNS, security group egress/ingress, or load balancer health checks to resolve graph-to-runtime discrepancy.',
          metadata: {
            declaredReachable: exp.declaredReachable,
            liveReachable: probe.reachable,
            probeLatencyMs: probe.latencyMs,
          },
        });
      }

      // 2. Auth Enforcement Disagreement
      if (exp.declaredRequiresAuth && !probe.authRequired && probe.reachable && probe.httpStatus === 200) {
        findings.push({
          id: `finding-disagreement-auth-${exp.assetId}`,
          tenantId: exp.tenantId,
          assetId: exp.assetId,
          category: 'MODEL_DISAGREEMENT',
          ruleId: 'LIVE-VAL-002',
          title: `Model Disagreement: Declared Protected Endpoint Grants Unauthenticated Access (${exp.endpointUrl})`,
          description: `Graph model asserts this endpoint requires authentication, but unauthenticated live probe returned HTTP 200 OK. Declared State: REQUIRES_AUTH. Live Observed: UNAUTHENTICATED_ACCESS_ALLOWED.`,
          severity: 'CRITICAL',
          confidence: 'CERTAIN',
          scanner: 'live-validation-engine',
          evidence: createEvidence({
            id: `ev-auth-disagree-${exp.assetId}`,
            tenantId: exp.tenantId,
            sourceType: 'RUNTIME_TRACE',
            repository: 'infrastructure/live',
            filePath: exp.endpointUrl,
            lineStart: 1,
            lineEnd: 1,
            snippet: `Declared expectation: requiresAuth=true. Live probe returned HTTP ${probe.httpStatus} unauthenticated.`,
            scanner: 'live-validation-engine',
          }),
          remediationRecommendation: 'Immediately re-enable authentication middleware / API gateway authorizer on the live endpoint.',
          metadata: {
            declaredRequiresAuth: exp.declaredRequiresAuth,
            liveHttpStatus: probe.httpStatus,
          },
        });
      }
    }

    return findings;
  }
}
