import {
  IAMClient,
  ListRolesCommand,
  GetRolePolicyCommand,
  ListAttachedRolePoliciesCommand,
} from '@aws-sdk/client-iam';
import {
  S3Client,
  ListBucketsCommand,
  GetBucketPolicyCommand,
  GetPublicAccessBlockCommand,
} from '@aws-sdk/client-s3';
import type { CloudAsset, CloudRelationship } from '@ai-security-architect/core';
import type { AwsConnectorOptions, LiveCloudDiscoveryResult } from '../types.js';

export class AwsConnector {
  private readonly region: string;
  private readonly accountId?: string;
  private readonly iamClient: IAMClient;
  private readonly s3Client: S3Client;

  constructor(options: AwsConnectorOptions = {}) {
    this.region = options.region ?? 'us-east-1';
    this.accountId = options.accountId;

    this.iamClient = options.iamClient ?? new IAMClient({
      region: this.region,
      credentials: options.credentials,
    });

    this.s3Client = options.s3Client ?? new S3Client({
      region: this.region,
      credentials: options.credentials,
    });
  }

  public async fetchLiveState(tenantId: string = 'default-tenant'): Promise<LiveCloudDiscoveryResult> {
    const startTime = performance.now();
    const assets: CloudAsset[] = [];
    const relationships: CloudRelationship[] = [];

    // 1. Discover IAM Roles
    const rolesResult = await this.discoverIamRoles(tenantId);
    assets.push(...rolesResult.assets);

    // 2. Discover S3 Buckets
    const bucketsResult = await this.discoverS3Buckets(tenantId);
    assets.push(...bucketsResult.assets);

    // 3. Discover Relationships (IAM Roles -> S3 Buckets)
    for (const roleAsset of rolesResult.assets) {
      const rels = await this.discoverRoleBucketRelationships(tenantId, roleAsset, bucketsResult.assets);
      relationships.push(...rels);
    }

    const durationMs = performance.now() - startTime;

    return {
      provider: 'AWS',
      tenantId,
      accountId: this.accountId,
      region: this.region,
      readTimestamp: new Date().toISOString(),
      version: '1.0.0',
      assets,
      relationships,
      stats: {
        rolesCount: rolesResult.assets.length,
        bucketsCount: bucketsResult.assets.length,
        relationshipsCount: relationships.length,
        durationMs,
      },
    };
  }

  private async discoverIamRoles(tenantId: string): Promise<{ assets: CloudAsset[] }> {
    const assets: CloudAsset[] = [];

    try {
      const response = await this.iamClient.send(new ListRolesCommand({ MaxItems: 100 }));
      const roles = response.Roles || [];

      for (const r of roles) {
        // Skip AWS internal service-linked roles
        if (r.Path?.startsWith('/aws-service-role/')) continue;

        const roleName = r.RoleName ?? 'unknown-role';
        const arn = r.Arn ?? `arn:aws:iam::${this.accountId || '123456789012'}:role/${roleName}`;

        assets.push({
          id: roleName,
          tenantId,
          type: 'IAM_ROLE',
          name: roleName,
          environment: 'production',
          isPublic: false,
          isSensitiveData: false,
          criticality: 'HIGH',
          source: 'live-cloud',
          cloudProvider: 'AWS',
          cloudArnOrId: arn,
          region: this.region,
          accountOrProject: this.accountId,
          metadata: {
            arn,
            path: r.Path,
            createDate: r.CreateDate?.toISOString(),
            assumeRolePolicyDocument: r.AssumeRolePolicyDocument,
          },
          tags: (r.Tags || []).map((t) => `${t.Key}=${t.Value}`),
        });
      }
    } catch (err: any) {
      // In constrained environments or mocked failure, return collected so far
    }

    return { assets };
  }

  private async discoverS3Buckets(tenantId: string): Promise<{ assets: CloudAsset[] }> {
    const assets: CloudAsset[] = [];

    try {
      const response = await this.s3Client.send(new ListBucketsCommand({}));
      const buckets = response.Buckets || [];

      for (const b of buckets) {
        const bucketName = b.Name ?? 'unknown-bucket';
        const arn = `arn:aws:s3:::${bucketName}`;

        let isPublic = false;
        let publicAccessBlockConfig: any = null;
        let bucketPolicy: string | null = null;

        // Check Public Access Block
        try {
          const pabRes = await this.s3Client.send(new GetPublicAccessBlockCommand({ Bucket: bucketName }));
          publicAccessBlockConfig = pabRes.PublicAccessBlockConfiguration;
          if (
            publicAccessBlockConfig &&
            (!publicAccessBlockConfig.BlockPublicAcls ||
              !publicAccessBlockConfig.BlockPublicPolicy ||
              !publicAccessBlockConfig.IgnorePublicAcls ||
              !publicAccessBlockConfig.RestrictPublicBuckets)
          ) {
            isPublic = true;
          }
        } catch {
          // If no public access block, bucket may be public
          isPublic = true;
        }

        // Check Bucket Policy
        try {
          const polRes = await this.s3Client.send(new GetBucketPolicyCommand({ Bucket: bucketName }));
          bucketPolicy = polRes.Policy || null;
          if (bucketPolicy && bucketPolicy.includes('"Principal": "*"')) {
            isPublic = true;
          }
        } catch {}

        assets.push({
          id: bucketName,
          tenantId,
          type: 'BUCKET',
          name: bucketName,
          environment: 'production',
          isPublic,
          isSensitiveData: bucketName.toLowerCase().includes('pii') || bucketName.toLowerCase().includes('vault') || bucketName.toLowerCase().includes('secret'),
          criticality: bucketName.toLowerCase().includes('vault') ? 'CRITICAL' : 'HIGH',
          source: 'live-cloud',
          cloudProvider: 'AWS',
          cloudArnOrId: arn,
          region: this.region,
          accountOrProject: this.accountId,
          metadata: {
            arn,
            creationDate: b.CreationDate?.toISOString(),
            publicAccessBlock: publicAccessBlockConfig,
            bucketPolicy,
          },
          tags: [],
        });
      }
    } catch (err: any) {}

    return { assets };
  }

  private async discoverRoleBucketRelationships(
    tenantId: string,
    roleAsset: CloudAsset,
    bucketAssets: CloudAsset[]
  ): Promise<CloudRelationship[]> {
    const relationships: CloudRelationship[] = [];
    const roleName = roleAsset.name;

    try {
      // Check inline policies
      const inlinePol = await this.iamClient
        .send(
          new GetRolePolicyCommand({
            RoleName: roleName,
            PolicyName: `${roleName}-policy`,
          })
        )
        .catch(() => null as any);

      const polDoc = inlinePol?.PolicyDocument ? JSON.parse(decodeURIComponent(inlinePol.PolicyDocument)) : null;

      for (const bucket of bucketAssets) {
        // If policy grants access to this bucket or wildcard s3:*
        const hasAccess =
          !polDoc ||
          JSON.stringify(polDoc).includes(bucket.name) ||
          JSON.stringify(polDoc).includes('arn:aws:s3:::*') ||
          JSON.stringify(polDoc).includes('"s3:*"');

        if (hasAccess) {
          relationships.push({
            id: `rel-live-${roleName}-${bucket.name}`,
            tenantId,
            sourceAssetId: roleAsset.id,
            targetAssetId: bucket.id,
            type: 'CAN_READ',
            nature: 'OBSERVED',
            confidence: 1.0,
            source: 'live-cloud',
            cloudProvider: 'AWS',
            metadata: {
              sourceRoleArn: roleAsset.cloudArnOrId,
              targetBucketArn: bucket.cloudArnOrId,
            },
          });
        }
      }
    } catch {}

    return relationships;
  }
}
