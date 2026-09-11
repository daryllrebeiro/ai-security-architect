import { describe, it, expect, vi } from 'vitest';
import {
  WebhookDispatcher,
  type WebhookDestination,
  type DispatchPayload,
  type HttpTransport,
} from '../src/index.js';

describe('Task 2.4: Enterprise SIEM & Webhook Dispatcher', () => {
  const samplePayload: DispatchPayload = {
    tenantId: 'tenant-enterprise-01',
    repository: 'github.com/org/payments',
    attackPathId: 'path-999',
    riskScore: 9.6,
    entryPoint: 'public-alb',
    targetAsset: 's3-customer-pii-vault',
    stepsSummary: [
      'Public ALB exposes HTTP',
      'ALB routes to payment-service pod (SSRF vulnerable)',
      'Pod assumes payment-role via IAM',
      'Role grants wildcard CAN_READ on s3-customer-pii-vault',
    ],
    recommendedAction: 'Restrict IAM policy trust on payment-service to least-privilege',
  };

  it('formats Slack Block Kit payloads with alert card, risk score, and choke point action', () => {
    const dispatcher = new WebhookDispatcher();
    const dest: WebhookDestination = {
      id: 'slack-alerts',
      name: 'Security Ops Slack',
      type: 'SLACK',
      url: 'https://slack.internal.corp/mock-webhook',
      enabled: true,
      minRiskThreshold: 8.0,
    };

    const formattedJson = dispatcher.formatPayload(dest, samplePayload);
    const parsed = JSON.parse(formattedJson);

    expect(parsed.blocks).toBeDefined();
    expect(parsed.blocks[0].text.text).toContain('Critical Attack Path Alert (9.6/10.0)');
    expect(formattedJson).toContain('s3-customer-pii-vault');
    expect(formattedJson).toContain('Restrict IAM policy trust');
  });

  it('formats Microsoft Teams and Jira webhook payloads correctly', () => {
    const dispatcher = new WebhookDispatcher();

    // Teams
    const teamsDest: WebhookDestination = {
      id: 'teams-sec',
      name: 'Teams Sec',
      type: 'TEAMS',
      url: 'https://outlook.office.com/webhook/xxx',
      enabled: true,
      minRiskThreshold: 7.0,
    };
    const teamsJson = dispatcher.formatPayload(teamsDest, samplePayload);
    const teamsParsed = JSON.parse(teamsJson);
    expect(teamsParsed['@type']).toBe('MessageCard');
    expect(teamsParsed.sections[0].activityTitle).toContain('public-alb ➔ s3-customer-pii-vault');

    // Jira
    const jiraDest: WebhookDestination = {
      id: 'jira-board',
      name: 'Jira Sec Board',
      type: 'JIRA',
      url: 'https://jira.enterprise.com/rest/api/2/issue',
      enabled: true,
      minRiskThreshold: 7.0,
    };
    const jiraJson = dispatcher.formatPayload(jiraDest, samplePayload);
    const jiraParsed = JSON.parse(jiraJson);
    expect(jiraParsed.fields.summary).toContain('[Security] Attack Path');
    expect(jiraParsed.fields.issuetype.name).toBe('Bug');
    expect(jiraParsed.fields.priority.name).toBe('Highest');
  });

  it('redacts tokens and credentials from URLs and headers', () => {
    const dispatcher = new WebhookDispatcher();

    const sensitiveUrl = 'https://siem.corp.com/hec?token=secret-token-12345&key=my-key';
    const redactedUrl = dispatcher.redactUrl(sensitiveUrl);
    expect(redactedUrl).not.toContain('secret-token-12345');
    expect(redactedUrl).not.toContain('my-key');
    expect(redactedUrl).toContain('token=***');

    const sensitiveHeaders = {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer super-secret-jwt',
      'X-Api-Key': 'key-98765',
    };
    const redactedHeaders = dispatcher.redactHeaders(sensitiveHeaders);
    expect(redactedHeaders['Authorization']).toBe('***REDACTED***');
    expect(redactedHeaders['X-Api-Key']).toBe('***REDACTED***');
    expect(redactedHeaders['Content-Type']).toBe('application/json');
  });

  it('retries with exponential backoff on transient errors and succeeds upon recovery', async () => {
    let attempts = 0;
    const mockTransport: HttpTransport = async () => {
      attempts++;
      if (attempts < 3) {
        return { ok: false, status: 503, text: async () => 'Service Unavailable' };
      }
      return { ok: true, status: 200, text: async () => '{"ok": true}' };
    };

    const dispatcher = new WebhookDispatcher({
      transport: mockTransport,
      maxRetries: 3,
      baseBackoffMs: 10,
    });

    const dest: WebhookDestination = {
      id: 'mock-webhook',
      name: 'Mock Webhook',
      type: 'SLACK',
      url: 'https://mock.com/webhook',
      enabled: true,
      minRiskThreshold: 7.0,
    };

    const result = await dispatcher.dispatchSingle(dest, samplePayload);
    expect(result.success).toBe(true);
    expect(result.attempts).toBe(3);
    expect(result.statusCode).toBe(200);
  });

  it('skips disabled destinations and routes below minRiskThreshold', async () => {
    const mockTransport = vi.fn().mockResolvedValue({ ok: true, status: 200, text: async () => 'ok' });
    const dispatcher = new WebhookDispatcher({ transport: mockTransport });

    const destinations: WebhookDestination[] = [
      {
        id: 'disabled-dest',
        name: 'Disabled',
        type: 'SLACK',
        url: 'https://example.com/1',
        enabled: false,
        minRiskThreshold: 5.0,
      },
      {
        id: 'high-threshold-dest',
        name: 'Strict 9.8+',
        type: 'TEAMS',
        url: 'https://example.com/2',
        enabled: true,
        minRiskThreshold: 9.8, // samplePayload is 9.6 -> should skip
      },
      {
        id: 'matching-dest',
        name: 'SIEM',
        type: 'GENERIC_SIEM',
        url: 'https://example.com/3',
        enabled: true,
        minRiskThreshold: 7.0,
      },
    ];

    const results = await dispatcher.dispatchAll(destinations, samplePayload);
    expect(results).toHaveLength(3);

    expect(results[0].success).toBe(false);
    expect(results[0].error).toContain('disabled');

    expect(results[1].success).toBe(false);
    expect(results[1].error).toContain('below threshold');

    expect(results[2].success).toBe(true);
    expect(mockTransport).toHaveBeenCalledTimes(1);
  });
});
