import { describe, it, expect, vi } from 'vitest';
import {
  WebhookDispatcher,
  validateWebhookUrl,
  type WebhookDestination,
  type DispatchPayload,
} from '../src/index.js';

describe('Milestone 1.2: SSRF Egress Defense for Webhook Dispatcher', () => {
  const samplePayload: DispatchPayload = {
    tenantId: 'tenant-test',
    repository: 'github.com/org/repo',
    attackPathId: 'path-1',
    riskScore: 9.0,
    entryPoint: 'ingress-gw',
    targetAsset: 'db-master',
    stepsSummary: ['ingress to db'],
  };

  it('blocks AWS IMDS IP 169.254.169.254 and link-local ranges', () => {
    expect(validateWebhookUrl('http://169.254.169.254/latest/meta-data/').allowed).toBe(false);
    expect(validateWebhookUrl('http://169.254.1.1/').allowed).toBe(false);
  });

  it('blocks GCP metadata endpoints', () => {
    expect(validateWebhookUrl('http://metadata.google.internal/computeMetadata/v1/').allowed).toBe(false);
    expect(validateWebhookUrl('http://metadata.internal/').allowed).toBe(false);
  });

  it('blocks localhost and loopback addresses by default', () => {
    expect(validateWebhookUrl('http://127.0.0.1:8080/hook').allowed).toBe(false);
    expect(validateWebhookUrl('http://localhost:9000/webhook').allowed).toBe(false);
    expect(validateWebhookUrl('http://0.0.0.0:3000/').allowed).toBe(false);

    // Allowed when explicit flag is provided
    expect(validateWebhookUrl('http://127.0.0.1:8080/hook', { allowLocalhost: true }).allowed).toBe(true);
    expect(validateWebhookUrl('http://localhost:9000/webhook', { allowLocalhost: true }).allowed).toBe(true);
  });

  it('blocks RFC 1918 private IP ranges by default', () => {
    expect(validateWebhookUrl('http://10.0.1.5/webhook').allowed).toBe(false);
    expect(validateWebhookUrl('http://172.16.50.1/webhook').allowed).toBe(false);
    expect(validateWebhookUrl('http://192.168.1.100/alert').allowed).toBe(false);

    // Permitted if allowPrivateIps is set
    expect(validateWebhookUrl('http://10.0.1.5/webhook', { allowPrivateIps: true }).allowed).toBe(true);
    expect(validateWebhookUrl('http://192.168.1.100/alert', { allowPrivateIps: true }).allowed).toBe(true);
  });

  it('allows standard public webhooks', () => {
    expect(validateWebhookUrl('https://hooks.slack.com/services/T00/B00/X00').allowed).toBe(true);
    expect(validateWebhookUrl('https://api.pagerduty.com/events').allowed).toBe(true);
    expect(validateWebhookUrl('https://siem.example.com/api/v1').allowed).toBe(true);
  });

  it('rejects non-HTTP protocols', () => {
    expect(validateWebhookUrl('file:///etc/passwd').allowed).toBe(false);
    expect(validateWebhookUrl('gopher://127.0.0.1:70/').allowed).toBe(false);
    expect(validateWebhookUrl('ftp://example.com/payload').allowed).toBe(false);
  });

  it('prevents WebhookDispatcher from invoking transport when URL is blocked by SSRF defense', async () => {
    const mockTransport = vi.fn();
    const dispatcher = new WebhookDispatcher({ transport: mockTransport });

    const imdsDest: WebhookDestination = {
      id: 'imds-attack',
      name: 'Malicious Destination',
      type: 'GENERIC_SIEM',
      url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials',
      enabled: true,
      minRiskThreshold: 7.0,
    };

    const result = await dispatcher.dispatchSingle(imdsDest, samplePayload);
    expect(result.success).toBe(false);
    expect(result.attempts).toBe(0);
    expect(result.error).toContain('SSRF Blocked');
    expect(mockTransport).not.toHaveBeenCalled();
  });
});
