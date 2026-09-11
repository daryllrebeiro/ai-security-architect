import * as fs from 'node:fs/promises';
import { PermissionUsageInferrer, PolicyRightSizer } from '@ai-security-architect/remediation';
import { executeScan } from './scan.js';
import type { CliLeastPrivilegeOptions } from '../types.js';

export async function executeLeastPrivilege(options: CliLeastPrivilegeOptions): Promise<unknown> {
  const scanResult = await executeScan({
    path: options.path,
    tenantId: options.tenantId,
    silent: true,
  });

  const grantedActions = ['s3:GetObject', 's3:PutObject', 's3:DeleteObject', 's3:*', 'iam:PassRole'];
  const exercisedCode = `
    const s3 = new S3Client();
    await s3.getObject({ Bucket: 'my-bucket', Key: 'data.json' });
  `;

  const samplePolicyDoc = JSON.stringify(
    {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Action: grantedActions,
          Resource: '*',
        },
      ],
    },
    null,
    2
  );

  const inference = PermissionUsageInferrer.analyzeSource(exercisedCode, 'src/service.ts');
  const recommendation = PolicyRightSizer.recommend(
    {
      policyId: options.roleId || 'arn:aws:iam::123456789012:policy/AppPolicy',
      policyFilePath: 'infra/iam/policy.json',
      policyDocument: samplePolicyDoc,
      grantedActions,
      minConfidenceThreshold: 0.7,
    },
    inference
  );

  const outputStr = JSON.stringify(recommendation, null, 2);
  console.log(outputStr);

  if (options.outputFile) {
    await fs.writeFile(options.outputFile, outputStr, 'utf-8');
    console.log(`\n[Least-Privilege] Saved recommendation to ${options.outputFile}`);
  }

  return recommendation;
}
