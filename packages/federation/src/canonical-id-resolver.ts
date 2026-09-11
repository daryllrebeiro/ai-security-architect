import type { Asset } from '@ai-security-architect/core';

export class CanonicalIdResolver {
  /**
   * Resolves the canonical cloud identity for an asset, if present.
   * STRICT ENTERPRISE RULE: Never merges on generic asset names.
   * Only exact AWS ARNs, GCP URIs, Azure Resource IDs, or VPC IDs are canonical.
   */
  public static resolveCanonicalCloudId(asset: Asset): string | null {
    const candidates = [
      asset.metadata?.arn,
      asset.metadata?.cloudResourceId,
      asset.metadata?.resourceId,
      asset.metadata?.uri,
      asset.id,
    ];

    for (const candidate of candidates) {
      if (typeof candidate === 'string' && this.isValidCloudIdentity(candidate)) {
        return candidate.trim();
      }
    }

    return null;
  }

  public static isValidCloudIdentity(id: string): boolean {
    const trimmed = id.trim();

    // 1. AWS ARN
    if (/^arn:aws[a-zA-Z-]*:[a-zA-Z0-9-]*:[a-z0-9-]*:[0-9]*:.+$/i.test(trimmed)) {
      return true;
    }

    // 2. GCP Resource URI
    if (/^\/\/[a-z0-9-]+\.googleapis\.com\/.+$/i.test(trimmed) || /^projects\/[a-z0-9-]+\/.+$/i.test(trimmed)) {
      return true;
    }

    // 3. Azure Resource ID
    if (/^\/subscriptions\/[a-f0-9-]+\/resourceGroups\/.+$/i.test(trimmed)) {
      return true;
    }

    // 4. Shared VPC ID
    if (/^vpc-[a-f0-9]{8,17}$/i.test(trimmed)) {
      return true;
    }

    return false;
  }
}
