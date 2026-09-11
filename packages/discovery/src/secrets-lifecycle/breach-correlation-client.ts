import { createHash } from 'crypto';

export interface BreachCorrelationConfig {
  enabled: boolean;
  serviceUrl?: string; // e.g. "https://api.pwnedpasswords.com"
  kAnonymityPrefixLength?: number; // default: 5
  acceptOutboundHashLookup: boolean; // explicit org consent gate
}

export interface BreachMatchResult {
  isCompromised: boolean;
  occurrences: number;
  hashPrefixUsed: string;
  serviceQueried: string;
  sourceLabel: string;
}

export class BreachCorrelationClient {
  private config: BreachCorrelationConfig;
  private fetchFn: typeof fetch;

  constructor(config: BreachCorrelationConfig, customFetch?: typeof fetch) {
    this.config = {
      kAnonymityPrefixLength: 5,
      serviceUrl: 'https://api.pwnedpasswords.com',
      ...config,
    };
    this.fetchFn = customFetch || globalThis.fetch;
  }

  /**
   * Check if a secret is known to be compromised via k-anonymity range lookup.
   * STRICT SAFETY GUARANTEE: Raw secret is NEVER included in outbound URL or payload.
   */
  async checkSecret(rawSecret: string): Promise<BreachMatchResult> {
    if (!this.config.enabled || !this.config.acceptOutboundHashLookup) {
      throw new Error(
        'Breach correlation is disabled or requires explicit opt-in confirmation (acceptOutboundHashLookup: true).'
      );
    }

    if (!rawSecret || rawSecret.trim().length === 0) {
      return {
        isCompromised: false,
        occurrences: 0,
        hashPrefixUsed: '',
        serviceQueried: this.config.serviceUrl || '',
        sourceLabel: '(Breach Correlation Check: Disabled / Empty Secret)',
      };
    }

    // 1. Compute full SHA-1 uppercase hash locally
    const sha1Hash = createHash('sha1').update(rawSecret).digest('hex').toUpperCase();
    const prefixLen = this.config.kAnonymityPrefixLength ?? 5;
    const prefix = sha1Hash.substring(0, prefixLen);
    const suffix = sha1Hash.substring(prefixLen);

    // 2. Query range API with ONLY the 5-char prefix
    const url = `${this.config.serviceUrl}/range/${prefix}`;
    
    // Explicit security invariant assertion: Outbound path or query must NOT contain raw secret
    try {
      const parsedUrl = new URL(url);
      if (parsedUrl.pathname.includes(rawSecret) || parsedUrl.search.includes(rawSecret)) {
        throw new Error('SECURITY INVARIANT VIOLATION: Raw secret detected in outbound request URL path or query!');
      }
    } catch (e: any) {
      if (e.message?.includes('SECURITY INVARIANT VIOLATION')) throw e;
      if (url.includes(rawSecret)) {
        throw new Error('SECURITY INVARIANT VIOLATION: Raw secret detected in outbound request URL!');
      }
    }

    const response = await this.fetchFn(url, {
      method: 'GET',
      headers: {
        'Accept': 'text/plain',
        'User-Agent': 'ai-security-architect-k-anonymity-client',
      },
    });

    if (!response.ok) {
      throw new Error(`Breach correlation service returned HTTP ${response.status}: ${response.statusText}`);
    }

    const bodyText = await response.text();

    // 3. Match suffix locally
    const lines = bodyText.split('\n');
    for (const line of lines) {
      const [entrySuffix, countStr] = line.trim().split(':');
      if (entrySuffix && entrySuffix.toUpperCase() === suffix) {
        const count = parseInt(countStr || '1', 10);
        return {
          isCompromised: true,
          occurrences: isNaN(count) ? 1 : count,
          hashPrefixUsed: prefix,
          serviceQueried: this.config.serviceUrl || '',
          sourceLabel: '(Externally-Sourced Breach Correlation via K-Anonymity SHA-1 Range Query)',
        };
      }
    }

    return {
      isCompromised: false,
      occurrences: 0,
      hashPrefixUsed: prefix,
      serviceQueried: this.config.serviceUrl || '',
      sourceLabel: '(Externally-Sourced Breach Correlation via K-Anonymity SHA-1 Range Query: No Match)',
    };
  }
}
