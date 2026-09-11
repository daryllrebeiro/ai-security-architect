import { describe, it, expect, vi } from 'vitest';
import {
  LiveValidator,
  DisallowedEndpointError,
  DeclaredGraphExpectation,
  ProbeResult,
} from '../src/index.js';

describe('Task H.1: Continuous Live Validation (Security Chaos Engineering)', () => {
  const allowedEndpoints = [
    'https://api.production.internal/health',
    'https://api.production.internal/admin',
  ];

  it('probes allowlisted endpoint and reconciles matching expectations with zero disagreement findings', async () => {
    const mockFetch = vi.fn(async (url: string | URL | Request) => {
      const urlStr = url.toString();
      if (urlStr.includes('/admin')) {
        return {
          status: 401,
          ok: false,
        } as unknown as Response;
      }
      return {
        status: 200,
        ok: true,
      } as unknown as Response;
    });

    const validator = new LiveValidator(
      {
        enabled: true,
        allowedEndpoints,
      },
      mockFetch as unknown as typeof fetch
    );

    const probe1 = await validator.probeEndpoint('https://api.production.internal/health');
    const probe2 = await validator.probeEndpoint('https://api.production.internal/admin');

    const expectations: DeclaredGraphExpectation[] = [
      {
        assetId: 'asset-api-health',
        tenantId: 'tenant-1',
        endpointUrl: 'https://api.production.internal/health',
        declaredReachable: true,
        declaredRequiresAuth: false,
      },
      {
        assetId: 'asset-api-admin',
        tenantId: 'tenant-1',
        endpointUrl: 'https://api.production.internal/admin',
        declaredReachable: true,
        declaredRequiresAuth: true,
      },
    ];

    const findings = validator.reconcile(expectations, [probe1, probe2]);
    expect(findings.length).toBe(0);
  });

  it('raises distinct MODEL_DISAGREEMENT findings when live observations contradict declared graph', () => {
    const validator = new LiveValidator({
      enabled: true,
      allowedEndpoints,
    });

    const expectations: DeclaredGraphExpectation[] = [
      {
        assetId: 'asset-api-health',
        tenantId: 'tenant-1',
        endpointUrl: 'https://api.production.internal/health',
        declaredReachable: true, // Graph expects reachable
        declaredRequiresAuth: false,
      },
      {
        assetId: 'asset-api-admin',
        tenantId: 'tenant-1',
        endpointUrl: 'https://api.production.internal/admin',
        declaredReachable: true,
        declaredRequiresAuth: true, // Graph expects auth required
      },
    ];

    const contradictoryProbes: ProbeResult[] = [
      {
        endpointUrl: 'https://api.production.internal/health',
        reachable: false, // Disagreement 1: actually unreachable
        authRequired: false,
        tlsValid: true,
        latencyMs: 12,
        error: 'ECONNREFUSED',
      },
      {
        endpointUrl: 'https://api.production.internal/admin',
        reachable: true,
        httpStatus: 200, // Disagreement 2: auth bypass (returned 200 instead of 401/403)
        authRequired: false,
        tlsValid: true,
        latencyMs: 15,
      },
    ];

    const findings = validator.reconcile(expectations, contradictoryProbes);
    expect(findings.length).toBe(2);

    const reachabilityFinding = findings.find((f) => f.ruleId === 'LIVE-VAL-001')!;
    expect(reachabilityFinding).toBeDefined();
    expect(reachabilityFinding.category).toBe('MODEL_DISAGREEMENT');
    expect(reachabilityFinding.title).toContain('Declared Reachable Endpoint is Live Unreachable');

    const authFinding = findings.find((f) => f.ruleId === 'LIVE-VAL-002')!;
    expect(authFinding).toBeDefined();
    expect(authFinding.category).toBe('MODEL_DISAGREEMENT');
    expect(authFinding.severity).toBe('CRITICAL');
    expect(authFinding.title).toContain('Grants Unauthenticated Access');
  });

  it('strictly blocks probing against endpoints not explicitly in the allowlist', async () => {
    const validator = new LiveValidator({
      enabled: true,
      allowedEndpoints: ['https://allowed.example.com'],
    });

    await expect(validator.probeEndpoint('https://evil-unauthorized.example.com')).rejects.toThrow(
      DisallowedEndpointError
    );
  });
});
