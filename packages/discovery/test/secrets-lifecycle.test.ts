import { describe, it, expect, vi } from 'vitest';
import { Asset } from '@ai-security-architect/core';
import {
  SecretLifecycleTracker,
  BreachCorrelationClient,
} from '../src/secrets-lifecycle/index.js';

describe('Task G.1: Secrets Lifecycle & Credential Rotation Tracking', () => {
  it('correctly tracks credential age across simulated scans and flags rotation overdue past threshold', async () => {
    const tracker = new SecretLifecycleTracker({ maxAgeDays: 90 });

    const secretAsset: Asset = {
      id: 'sec-db-password',
      tenantId: 'tenant-1',
      type: 'SECRET',
      name: 'production-postgres-credential',
      environment: 'production',
      isPublic: false,
      isSensitiveData: true,
      criticality: 'HIGH',
      tags: ['secret', 'database'],
      metadata: {},
    };

    // Scan 1: Day 0
    const day0 = new Date('2026-01-01T00:00:00Z');
    const resDay0 = await tracker.evaluateSecrets([secretAsset], day0);
    expect(resDay0.findings.length).toBe(0);
    expect(resDay0.summaries[0].ageDays).toBe(0);
    expect(resDay0.summaries[0].isOverdue).toBe(false);

    // Scan 2: Day 60 (under 90 day limit)
    const day60 = new Date('2026-03-02T00:00:00Z');
    const resDay60 = await tracker.evaluateSecrets([secretAsset], day60);
    expect(resDay60.findings.length).toBe(0);
    expect(resDay60.summaries[0].ageDays).toBe(60);
    expect(resDay60.summaries[0].isOverdue).toBe(false);

    // Scan 3: Day 120 (exceeds 90 day limit)
    const day120 = new Date('2026-05-01T00:00:00Z');
    const resDay120 = await tracker.evaluateSecrets([secretAsset], day120);
    expect(resDay120.findings.length).toBe(1);
    expect(resDay120.findings[0].category).toBe('CREDENTIAL_ROTATION_OVERDUE');
    expect(resDay120.findings[0].ruleId).toBe('SEC-LIFECYCLE-001');
    expect(resDay120.summaries[0].ageDays).toBe(120);
    expect(resDay120.summaries[0].isOverdue).toBe(true);

    // Scan 4: Day 125 with authoritative cloud rotation timestamp at Day 122
    const rotatedAsset: Asset = {
      ...secretAsset,
      metadata: {
        lastRotatedDate: '2026-05-03T00:00:00Z',
      },
    };
    const day125 = new Date('2026-05-06T00:00:00Z');
    const resDay125 = await tracker.evaluateSecrets([rotatedAsset], day125);
    // Age since last rotation is only 3 days -> rotation overdue is cleared!
    expect(resDay125.findings.length).toBe(0);
    expect(resDay125.summaries[0].daysSinceLastRotation).toBe(3);
    expect(resDay125.summaries[0].isOverdue).toBe(false);
  });

  it('safely queries breach correlation using k-anonymity SHA-1 prefix without leaking raw secret', async () => {
    const rawSecret = 'password';
    let capturedUrl = '';
    let capturedOptions: RequestInit | undefined;

    // SHA-1 of 'password': '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8'
    // Prefix: '5BAA6', Suffix: '1E4C9B93F3F0682250B6CF8331B7EE68FD8'

    const mockFetch = vi.fn(async (url: string | URL | Request, options?: RequestInit) => {
      capturedUrl = url.toString();
      capturedOptions = options;
      return {
        ok: true,
        status: 200,
        text: async () => '1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\nAAAAAFE6A6DDFE111CF314AE54D6954203D:1\n',
      } as unknown as Response;
    });

    const breachClient = new BreachCorrelationClient(
      {
        enabled: true,
        acceptOutboundHashLookup: true,
        serviceUrl: 'https://api.breach-service.test',
        kAnonymityPrefixLength: 5,
      },
      mockFetch as unknown as typeof fetch
    );

    const result = await breachClient.checkSecret(rawSecret);

    // 1. Assert on the outbound request: MUST NOT contain raw secret
    expect(capturedUrl).toBe('https://api.breach-service.test/range/5BAA6');
    expect(capturedUrl.includes(rawSecret)).toBe(false);
    expect(new URL(capturedUrl).pathname).toBe('/range/5BAA6');
    expect(capturedOptions?.body).toBeUndefined(); // GET request with no body

    // 2. Assert on local suffix matching result
    expect(result.isCompromised).toBe(true);
    expect(result.occurrences).toBe(42);
    expect(result.hashPrefixUsed).toBe('5BAA6');
    expect(result.sourceLabel).toContain('K-Anonymity SHA-1');
  });

  it('rejects breach query when explicit opt-in is absent', async () => {
    const breachClient = new BreachCorrelationClient({
      enabled: true,
      acceptOutboundHashLookup: false, // org did not consent
    });

    await expect(breachClient.checkSecret('any-secret')).rejects.toThrow(
      /Breach correlation is disabled or requires explicit opt-in confirmation/
    );
  });
});
