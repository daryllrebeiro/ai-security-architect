import type { CloudAsset, CloudRelationship, CloudProvider } from '@ai-security-architect/core';

export interface AwsConnectorOptions {
  region?: string;
  accountId?: string;
  credentials?: {
    accessKeyId: string;
    secretAccessKey: string;
    sessionToken?: string;
  };
  iamClient?: any;
  s3Client?: any;
}

export interface LiveCloudDiscoveryResult {
  provider: CloudProvider;
  tenantId: string;
  accountId?: string;
  region: string;
  readTimestamp: string;
  version: string;
  assets: CloudAsset[];
  relationships: CloudRelationship[];
  stats: {
    rolesCount: number;
    bucketsCount: number;
    relationshipsCount: number;
    durationMs: number;
  };
}

export interface CloudDiscoveryQueueOptions {
  ttlMinutes?: number;
  cacheFilePath?: string;
}
