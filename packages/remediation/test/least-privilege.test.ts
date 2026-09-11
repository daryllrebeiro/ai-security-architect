import { describe, it, expect } from 'vitest';
import {
  PermissionUsageInferrer,
  PolicyRightSizer,
} from '../src/index.js';

describe('Task E.1 — IAM Least-Privilege / Permission Right-Sizing Recommender', () => {
  it('scopes down broad granted policy to statically exercised actions as a unified diff', () => {
    const serviceCode = `
      import { S3Client } from '@aws-sdk/client-s3';
      const s3 = new S3Client({});

      export async function fetchDocument(key: string) {
        const doc = await s3.getObject({ Bucket: 'corp-docs', Key: key });
        const list = await s3.listObjectsV2({ Bucket: 'corp-docs' });
        return { doc, list };
      }
    `;

    const policyDoc = [
      'resource "aws_iam_policy" "reader_policy" {',
      '  name = "corp-docs-reader"',
      '  policy = jsonencode({',
      '    Statement = [{',
      '      Action = [',
      '        "s3:GetObject",',
      '        "s3:ListBucket",',
      '        "s3:PutObject",',
      '        "s3:DeleteObject",',
      '        "s3:PutBucketPolicy"',
      '      ]',
      '      Effect   = "Allow"',
      '      Resource = "*"',
      '    }]',
      '  })',
      '}',
    ].join('\n');

    const grantedActions = [
      's3:GetObject',
      's3:ListBucket',
      's3:PutObject',
      's3:DeleteObject',
      's3:PutBucketPolicy',
    ];

    const inference = PermissionUsageInferrer.analyzeSource(serviceCode, 'src/doc-reader.ts');

    expect(inference.exercisedActions).toContain('s3:GetObject');
    expect(inference.exercisedActions).toContain('s3:ListBucket');
    expect(inference.exercisedActions).not.toContain('s3:PutObject');
    expect(inference.observability.hasDynamicDispatch).toBe(false);
    expect(inference.observability.observabilityScore).toBe(1.0);

    const recommendation = PolicyRightSizer.recommend(
      {
        policyId: 'policy-reader-01',
        policyDocument: policyDoc,
        policyFilePath: 'terraform/s3_policy.tf',
        grantedActions,
      },
      inference
    );

    expect(recommendation.status).toBe('RECOMMENDED');
    expect(recommendation.confidenceScore).toBe(1.0);
    expect(recommendation.retainedActions).toEqual(['s3:GetObject', 's3:ListBucket']);
    expect(recommendation.removedActions).toEqual([
      's3:PutObject',
      's3:DeleteObject',
      's3:PutBucketPolicy',
    ]);
    expect(recommendation.isProvisional).toBe(true);

    expect(recommendation.unifiedDiff).toBeDefined();
    expect(recommendation.unifiedDiff).toContain('--- a/terraform/s3_policy.tf');
    expect(recommendation.unifiedDiff).toContain('+++ b/terraform/s3_policy.tf');
    expect(recommendation.unifiedDiff).toMatch(/-\s*"s3:PutObject"/);
    expect(recommendation.unifiedDiff).toMatch(/-\s*"s3:DeleteObject"/);
    expect(recommendation.unifiedDiff).toMatch(/-\s*"s3:PutBucketPolicy"/);
  });

  it('declines recommendation when workload exhibits dynamic dispatch or reflection', () => {
    const dynamicCode = `
      export async function executeDynamicOp(client: any, opName: string, payload: any) {
        // Dynamic dispatch via computed property
        return client[opName](payload);
      }

      export async function invokeEval(s3: any) {
        eval("s3.upload(payload)");
      }
    `;

    const grantedActions = ['s3:GetObject', 's3:PutObject', 's3:DeleteObject'];

    const inference = PermissionUsageInferrer.analyzeSource(dynamicCode, 'src/dynamic-client.ts');

    expect(inference.observability.hasDynamicDispatch).toBe(true);
    expect(inference.observability.dynamicPatternsDetectedCount).toBeGreaterThanOrEqual(2);
    expect(inference.observability.observabilityScore).toBeLessThan(0.5);

    const recommendation = PolicyRightSizer.recommend(
      {
        policyId: 'policy-dyn-01',
        policyDocument: 'Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]',
        policyFilePath: 'policy.tf',
        grantedActions,
      },
      inference
    );

    expect(recommendation.status).toBe('DECLINED_LOW_CONFIDENCE');
    expect(recommendation.removedActions).toHaveLength(0);
    expect(recommendation.explanation).toContain('Right-sizing recommendation declined');
    expect(recommendation.explanation).toContain('dynamic dispatch');
  });

  it('recognizes already least-privilege policy with zero unnecessary removals', () => {
    const code = `
      export async function writeItem(dynamodb: any, item: any) {
        return dynamodb.putItem(item);
      }
    `;

    const inference = PermissionUsageInferrer.analyzeSource(code, 'src/writer.ts');
    const recommendation = PolicyRightSizer.recommend(
      {
        policyId: 'policy-writer-01',
        policyDocument: 'Action = ["dynamodb:PutItem"]',
        policyFilePath: 'dynamo.tf',
        grantedActions: ['dynamodb:PutItem'],
      },
      inference
    );

    expect(recommendation.status).toBe('ALREADY_LEAST_PRIVILEGE');
    expect(recommendation.retainedActions).toEqual(['dynamodb:PutItem']);
    expect(recommendation.removedActions).toHaveLength(0);
  });
});
