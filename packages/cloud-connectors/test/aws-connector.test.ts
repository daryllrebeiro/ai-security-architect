import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { AwsConnector } from '../src/aws/aws-connector.js';
import { CloudDiscoveryQueue } from '../src/cloud-discovery-queue.js';

describe('AwsConnector', () => {
  it('discovers IAM roles and S3 buckets with permissions without network calls', async () => {
    const mockIamSend = vi.fn().mockImplementation((command: any) => {
      const name = command.constructor.name;
      if (name === 'ListRolesCommand' || name.includes('ListRoles')) {
        return Promise.resolve({
          Roles: [
            {
              RoleName: 'app-service-role',
              Arn: 'arn:aws:iam::123456789012:role/app-service-role',
              Path: '/',
              CreateDate: new Date('2026-01-01'),
            },
            {
              RoleName: 'aws-service-role-rds',
              Arn: 'arn:aws:iam::123456789012:role/aws-service-role/rds',
              Path: '/aws-service-role/',
            },
          ],
        });
      }
      if (name === 'GetRolePolicyCommand' || name.includes('GetRolePolicy')) {
        return Promise.resolve({
          PolicyDocument: encodeURIComponent(
            JSON.stringify({
              Statement: [
                {
                  Effect: 'Allow',
                  Action: ['s3:GetObject', 's3:ListBucket'],
                  Resource: ['arn:aws:s3:::customer-data-bucket', 'arn:aws:s3:::customer-data-bucket/*'],
                },
              ],
            })
          ),
        });
      }
      return Promise.resolve({});
    });

    const mockS3Send = vi.fn().mockImplementation((command: any) => {
      const name = command.constructor.name;
      if (name === 'ListBucketsCommand' || name.includes('ListBuckets')) {
        return Promise.resolve({
          Buckets: [
            {
              Name: 'customer-data-bucket',
              CreationDate: new Date('2026-01-01'),
            },
            {
              Name: 'public-assets-bucket',
              CreationDate: new Date('2026-01-01'),
            },
          ],
        });
      }
      if (name === 'GetPublicAccessBlockCommand' || name.includes('GetPublicAccessBlock')) {
        if (command.input.Bucket === 'customer-data-bucket') {
          return Promise.resolve({
            PublicAccessBlockConfiguration: {
              BlockPublicAcls: true,
              BlockPublicPolicy: true,
              IgnorePublicAcls: true,
              RestrictPublicBuckets: true,
            },
          });
        }
        return Promise.resolve({
          PublicAccessBlockConfiguration: {
            BlockPublicAcls: false,
            BlockPublicPolicy: false,
            IgnorePublicAcls: false,
            RestrictPublicBuckets: false,
          },
        });
      }
      return Promise.resolve({});
    });

    const mockIamClient = { send: mockIamSend };
    const mockS3Client = { send: mockS3Send };

    const connector = new AwsConnector({
      region: 'us-east-1',
      accountId: '123456789012',
      iamClient: mockIamClient as any,
      s3Client: mockS3Client as any,
    });

    const result = await connector.fetchLiveState('test-tenant');

    expect(result.provider).toBe('AWS');
    expect(result.assets.length).toBe(3); // 1 IAM role (service-role skipped), 2 buckets
    const roleAsset = result.assets.find((a) => a.id === 'app-service-role');
    expect(roleAsset).toBeDefined();
    expect(roleAsset?.source).toBe('live-cloud');
    expect(roleAsset?.type).toBe('IAM_ROLE');

    const privateBucket = result.assets.find((a) => a.id === 'customer-data-bucket');
    expect(privateBucket?.isPublic).toBe(false);

    const publicBucket = result.assets.find((a) => a.id === 'public-assets-bucket');
    expect(publicBucket?.isPublic).toBe(true);

    // Verify relationship mapped from role to customer-data-bucket
    expect(result.relationships.length).toBe(1);
    expect(result.relationships[0].sourceAssetId).toBe('app-service-role');
    expect(result.relationships[0].targetAssetId).toBe('customer-data-bucket');
    expect(result.relationships[0].source).toBe('live-cloud');
  });

  it('caches live cloud snapshots on disk for 15 minutes', async () => {
    const testCachePath = path.resolve(process.cwd(), '.sec-arch/cache/test-cloud-live.json');
    if (fs.existsSync(testCachePath)) {
      fs.unlinkSync(testCachePath);
    }

    const mockFetch = vi.fn().mockResolvedValue({
      provider: 'AWS',
      tenantId: 'test-tenant',
      region: 'us-east-1',
      readTimestamp: new Date().toISOString(),
      version: '1.0.0',
      assets: [],
      relationships: [],
      stats: { rolesCount: 0, bucketsCount: 0, relationshipsCount: 0, durationMs: 5 },
    });

    const mockConnector = {
      fetchLiveState: mockFetch,
    } as any;

    const queue = new CloudDiscoveryQueue({
      ttlMinutes: 15,
      cacheFilePath: testCachePath,
    });

    // First call triggers fetch
    const res1 = await queue.getLiveSnapshot(mockConnector, 'test-tenant');
    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(fs.existsSync(testCachePath)).toBe(true);

    // Second call uses disk cache
    const res2 = await queue.getLiveSnapshot(mockConnector, 'test-tenant');
    expect(mockFetch).toHaveBeenCalledTimes(1); // Still 1!
    expect(res2.tenantId).toBe(res1.tenantId);

    // Clean up
    queue.clearCache();
    expect(fs.existsSync(testCachePath)).toBe(false);
  });
});
