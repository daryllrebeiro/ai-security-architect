import {
  type WebhookDestination,
  type DispatchPayload,
  type DispatchResult,
} from './types.js';

export interface HttpResponse {
  ok: boolean;
  status: number;
  text(): Promise<string>;
}

export type HttpTransport = (url: string, init: RequestInit) => Promise<HttpResponse>;

export interface WebhookSsrfOptions {
  allowLocalhost?: boolean;
  allowPrivateIps?: boolean;
}

export function validateWebhookUrl(
  urlString: string,
  options: WebhookSsrfOptions = {}
): { allowed: boolean; reason?: string } {
  let url: URL;
  try {
    url = new URL(urlString);
  } catch {
    return { allowed: false, reason: `Invalid URL: ${urlString}` };
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { allowed: false, reason: `Forbidden protocol: ${url.protocol} (only http and https permitted)` };
  }

  const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');

  // Block Cloud Metadata endpoints
  const metadataHosts = ['instance-data', 'metadata.google.internal', 'metadata.internal', '169.254.169.254', 'fd00:ec2::254'];
  if (metadataHosts.includes(hostname)) {
    return { allowed: false, reason: `Access to Cloud Instance Metadata Service (${hostname}) is strictly prohibited` };
  }

  // Block localhost & loopbacks unless allowed
  if (
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname === '127.0.0.1' ||
    hostname === '0.0.0.0' ||
    hostname === '::1' ||
    hostname === '::'
  ) {
    if (!options.allowLocalhost) {
      return { allowed: false, reason: `Access to loopback/localhost (${hostname}) is prohibited` };
    }
  }

  // IPv4 checks
  const ipv4Match = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(hostname);
  if (ipv4Match) {
    const octets = [
      Number(ipv4Match[1]),
      Number(ipv4Match[2]),
      Number(ipv4Match[3]),
      Number(ipv4Match[4]),
    ];

    // Link-local / AWS IMDS (169.254.0.0/16)
    if (octets[0] === 169 && octets[1] === 254) {
      return { allowed: false, reason: `Access to link-local IP ${hostname} is prohibited` };
    }

    // Loopback (127.0.0.0/8 or 0.0.0.0)
    if (octets[0] === 127 || (octets[0] === 0 && octets[1] === 0 && octets[2] === 0 && octets[3] === 0)) {
      if (!options.allowLocalhost) {
        return { allowed: false, reason: `Access to loopback IP ${hostname} is prohibited` };
      }
    }

    // RFC 1918 private ranges:
    // 10.0.0.0 - 10.255.255.255
    // 172.16.0.0 - 172.31.255.255
    // 192.168.0.0 - 192.168.255.255
    const isPrivate =
      octets[0] === 10 ||
      (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
      (octets[0] === 192 && octets[1] === 168);

    if (isPrivate && !options.allowPrivateIps) {
      return { allowed: false, reason: `Access to RFC 1918 private IP ${hostname} is prohibited without explicit permission` };
    }
  }

  return { allowed: true };
}

export interface WebhookDispatcherOptions {
  transport?: HttpTransport;
  maxRetries?: number;
  baseBackoffMs?: number;
  allowLocalhost?: boolean;
  allowPrivateIps?: boolean;
}

export class WebhookDispatcher {
  private readonly transport: HttpTransport;
  private readonly maxRetries: number;
  private readonly baseBackoffMs: number;
  private readonly allowLocalhost: boolean;
  private readonly allowPrivateIps: boolean;

  constructor(options: WebhookDispatcherOptions = {}) {
    this.transport = options.transport ?? ((url, init) => fetch(url, init));
    this.maxRetries = options.maxRetries ?? 3;
    this.baseBackoffMs = options.baseBackoffMs ?? 200;
    this.allowLocalhost = options.allowLocalhost ?? false;
    this.allowPrivateIps = options.allowPrivateIps ?? false;
  }

  public redactUrl(url: string): string {
    try {
      const parsed = new URL(url);
      if (parsed.password) parsed.password = '***';
      if (parsed.searchParams.has('token')) parsed.searchParams.set('token', '***');
      if (parsed.searchParams.has('key')) parsed.searchParams.set('key', '***');
      if (parsed.searchParams.has('api_key')) parsed.searchParams.set('api_key', '***');
      return parsed.toString();
    } catch {
      return url.replace(/(token|key|secret)=[^&]+/gi, '$1=***');
    }
  }

  public redactHeaders(headers: Record<string, string>): Record<string, string> {
    const redacted: Record<string, string> = {};
    for (const [k, v] of Object.entries(headers)) {
      if (/auth|token|secret|key|cookie/i.test(k)) {
        redacted[k] = '***REDACTED***';
      } else {
        redacted[k] = v;
      }
    }
    return redacted;
  }

  public formatPayload(destination: WebhookDestination, payload: DispatchPayload): string {
    const timestamp = payload.timestamp ?? new Date().toISOString();

    switch (destination.type) {
      case 'SLACK':
        return JSON.stringify({
          blocks: [
            {
              type: 'header',
              text: {
                type: 'plain_text',
                text: `🚨 Critical Attack Path Alert (${payload.riskScore.toFixed(1)}/10.0)`,
              },
            },
            {
              type: 'section',
              fields: [
                { type: 'mrkdwn', text: `*Repository:*\n\`${payload.repository}\`` },
                { type: 'mrkdwn', text: `*Target Crown Jewel:*\n\`${payload.targetAsset}\`` },
                { type: 'mrkdwn', text: `*Entry Point:*\n\`${payload.entryPoint}\`` },
                { type: 'mrkdwn', text: `*Path ID:*\n\`${payload.attackPathId}\`` },
              ],
            },
            {
              type: 'section',
              text: {
                type: 'mrkdwn',
                text: `*Exploit Progression:*\n${payload.stepsSummary.map((s, i) => `${i + 1}. ${s}`).join('\n')}`,
              },
            },
            ...(payload.recommendedAction
              ? [
                  {
                    type: 'section',
                    text: {
                      type: 'mrkdwn',
                      text: `*🎯 Recommended Choke Point Action:*\n${payload.recommendedAction}`,
                    },
                  },
                ]
              : []),
            {
              type: 'context',
              elements: [
                {
                  type: 'mrkdwn',
                  text: `AI Security Architect | Tenant: ${payload.tenantId} | ${timestamp}`,
                },
              ],
            },
          ],
        });

      case 'TEAMS':
        return JSON.stringify({
          '@type': 'MessageCard',
          '@context': 'http://schema.org/extensions',
          themeColor: payload.riskScore >= 9.0 ? 'd93838' : 'ea8c10',
          summary: `Critical Attack Path Detected in ${payload.repository}`,
          sections: [
            {
              activityTitle: `🚨 Critical Attack Path: ${payload.entryPoint} ➔ ${payload.targetAsset}`,
              activitySubtitle: `Risk Score: ${payload.riskScore.toFixed(1)}/10.0 | Tenant: ${payload.tenantId}`,
              facts: [
                { name: 'Repository', value: payload.repository },
                { name: 'Target', value: payload.targetAsset },
                { name: 'Choke Point', value: payload.recommendedAction ?? 'N/A' },
              ],
              text: payload.stepsSummary.join(' ➔ '),
            },
          ],
        });

      case 'JIRA':
        return JSON.stringify({
          fields: {
            summary: `[Security] Attack Path from ${payload.entryPoint} to ${payload.targetAsset} (${payload.riskScore.toFixed(1)}/10.0)`,
            description: `Automated attack path detected by AI Security Architect.\n\n` +
              `*Risk Score:* ${payload.riskScore.toFixed(1)}/10.0\n` +
              `*Repository:* ${payload.repository}\n` +
              `*Entry Point:* ${payload.entryPoint}\n` +
              `*Crown Jewel:* ${payload.targetAsset}\n\n` +
              `*Attack Steps:*\n${payload.stepsSummary.map((s, i) => `${i + 1}. ${s}`).join('\n')}\n\n` +
              `*Remediation:*\n${payload.recommendedAction ?? 'Review architecture'}`,
            issuetype: { name: 'Bug' },
            priority: { name: payload.riskScore >= 9.0 ? 'Highest' : 'High' },
            labels: ['security', 'ai-security-architect', 'attack-path'],
          },
        });

      case 'GITHUB_PR_COMMENT':
        return JSON.stringify({
          body:
            payload.prCommentBody ??
            `### 🛡️ AI Security Architect Alert\n` +
              `**Repository:** \`${payload.repository}\`\n` +
              `**Path ID:** \`${payload.attackPathId}\` (Risk: **${payload.riskScore.toFixed(1)}/10.0**)\n` +
              `**Entrypoint:** \`${payload.entryPoint}\` ➔ **Target:** \`${payload.targetAsset}\`\n\n` +
              `**Exploit Progression:**\n${payload.stepsSummary.map((s, i) => `${i + 1}. ${s}`).join('\n')}\n\n` +
              (payload.recommendedAction ? `**🎯 Recommended Action:**\n${payload.recommendedAction}\n` : ''),
        });

      case 'GITLAB_PR_COMMENT':
        return JSON.stringify({
          body:
            payload.prCommentBody ??
            `### 🛡️ AI Security Architect Alert\n` +
              `**Repository:** \`${payload.repository}\`\n` +
              `**Path ID:** \`${payload.attackPathId}\` (Risk: **${payload.riskScore.toFixed(1)}/10.0**)\n` +
              `**Entrypoint:** \`${payload.entryPoint}\` ➔ **Target:** \`${payload.targetAsset}\`\n\n` +
              `**Exploit Progression:**\n${payload.stepsSummary.map((s, i) => `${i + 1}. ${s}`).join('\n')}\n\n` +
              (payload.recommendedAction ? `**🎯 Recommended Action:**\n${payload.recommendedAction}\n` : ''),
        });

      case 'GENERIC_SIEM':
      default:
        return JSON.stringify({
          event_type: 'ATTACK_PATH_DISCOVERED',
          source: 'ai-security-architect',
          tenant_id: payload.tenantId,
          repository: payload.repository,
          path_id: payload.attackPathId,
          risk_score: payload.riskScore,
          entry_point: payload.entryPoint,
          target_asset: payload.targetAsset,
          steps: payload.stepsSummary,
          recommended_action: payload.recommendedAction,
          timestamp,
        });
    }
  }

  public async dispatchSingle(
    destination: WebhookDestination,
    payload: DispatchPayload
  ): Promise<DispatchResult> {
    const timestamp = new Date().toISOString();

    if (!destination.enabled) {
      return {
        destinationId: destination.id,
        destinationType: destination.type,
        success: false,
        attempts: 0,
        error: 'Destination is disabled',
        timestamp,
      };
    }

    if (payload.riskScore < destination.minRiskThreshold) {
      return {
        destinationId: destination.id,
        destinationType: destination.type,
        success: false,
        attempts: 0,
        error: `Risk score ${payload.riskScore} below threshold ${destination.minRiskThreshold}`,
        timestamp,
      };
    }

    const ssrfCheck = validateWebhookUrl(destination.url, {
      allowLocalhost: this.allowLocalhost,
      allowPrivateIps: this.allowPrivateIps,
    });
    if (!ssrfCheck.allowed) {
      return {
        destinationId: destination.id,
        destinationType: destination.type,
        success: false,
        attempts: 0,
        error: `SSRF Blocked: ${ssrfCheck.reason}`,
        timestamp,
      };
    }

    const body = this.formatPayload(destination, payload);
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'ai-security-architect/0.1.0',
      ...(destination.headers || {}),
    };

    if (destination.authToken) {
      if (destination.type === 'GITLAB_PR_COMMENT') {
        headers['PRIVATE-TOKEN'] = destination.authToken;
      } else {
        headers['Authorization'] = `Bearer ${destination.authToken}`;
      }
    }

    if (destination.type === 'GITHUB_PR_COMMENT') {
      headers['Accept'] = headers['Accept'] || 'application/vnd.github+json';
      headers['X-GitHub-Api-Version'] = headers['X-GitHub-Api-Version'] || '2022-11-28';
    }

    let lastError: string | undefined;
    let statusCode: number | undefined;

    for (let attempt = 1; attempt <= this.maxRetries; attempt++) {
      try {
        const response = await this.transport(destination.url, {
          method: 'POST',
          headers,
          body,
        });

        statusCode = response.status;

        if (response.ok) {
          return {
            destinationId: destination.id,
            destinationType: destination.type,
            success: true,
            attempts: attempt,
            statusCode,
            timestamp,
          };
        } else {
          lastError = `HTTP ${response.status}: ${await response.text().catch(() => 'Unknown response')}`;
        }
      } catch (err: any) {
        lastError = err?.message ?? 'Network transport error';
      }

      // Exponential backoff
      if (attempt < this.maxRetries) {
        const delayMs = this.baseBackoffMs * Math.pow(2, attempt - 1);
        await new Promise((res) => setTimeout(res, delayMs));
      }
    }

    return {
      destinationId: destination.id,
      destinationType: destination.type,
      success: false,
      attempts: this.maxRetries,
      statusCode,
      error: lastError,
      timestamp,
    };
  }

  public async dispatchAll(
    destinations: WebhookDestination[],
    payload: DispatchPayload
  ): Promise<DispatchResult[]> {
    const promises = destinations.map((d) => this.dispatchSingle(d, payload));
    return Promise.all(promises);
  }
}
