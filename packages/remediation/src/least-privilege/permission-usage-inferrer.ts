import type {
  InferredPermissionUsage,
  PermissionInferenceResult,
  WorkloadObservabilityAnalysis,
} from './types.js';

export class PermissionUsageInferrer {
  private static readonly SDK_METHOD_TO_IAM: Record<string, string> = {
    // S3
    'getObject': 's3:GetObject',
    'selectObjectContent': 's3:GetObject',
    'listObjects': 's3:ListBucket',
    'listObjectsV2': 's3:ListBucket',
    'putObject': 's3:PutObject',
    'upload': 's3:PutObject',
    'deleteObject': 's3:DeleteObject',
    'deleteObjects': 's3:DeleteObject',
    // DynamoDB
    'getItem': 'dynamodb:GetItem',
    'batchGetItem': 'dynamodb:BatchGetItem',
    'putItem': 'dynamodb:PutItem',
    'batchWriteItem': 'dynamodb:BatchWriteItem',
    'updateItem': 'dynamodb:UpdateItem',
    'deleteItem': 'dynamodb:DeleteItem',
    'query': 'dynamodb:Query',
    'scan': 'dynamodb:Scan',
    // SQS
    'sendMessage': 'sqs:SendMessage',
    'sendMessageBatch': 'sqs:SendMessage',
    'receiveMessage': 'sqs:ReceiveMessage',
    'deleteMessage': 'sqs:DeleteMessage',
    'deleteMessageBatch': 'sqs:DeleteMessage',
    // SNS
    'publish': 'sns:Publish',
    // SecretsManager
    'getSecretValue': 'secretsmanager:GetSecretValue',
    'putSecretValue': 'secretsmanager:PutSecretValue',
    // KMS
    'decrypt': 'kms:Decrypt',
    'encrypt': 'kms:Encrypt',
    'generateDataKey': 'kms:GenerateDataKey',
  };

  private static readonly DYNAMIC_DISPATCH_PATTERNS = [
    /client\[\s*[a-zA-Z0-9_$]+\s*\]/i, // client[methodName]
    /invoke(?:Dynamic|Reflect|Generic)\s*\(/i,
    /eval\s*\(/i,
    /new\s+Proxy\s*\(/i,
    /Method\.invoke\s*\(/i, // Java reflection
    /Class\.forName\s*\(/i,
    /getattr\s*\(\s*(?:client|s3|db|svc)/i, // Python reflection
  ];

  public static analyzeSource(
    sourceContent: string,
    sourceFilePath: string
  ): PermissionInferenceResult {
    const lines = sourceContent.split('\n');
    const usageDetails: InferredPermissionUsage[] = [];
    const exercisedActions = new Set<string>();

    let dynamicPatternsCount = 0;
    const dynamicExplanations: string[] = [];

    lines.forEach((line, idx) => {
      const lineNum = idx + 1;

      // 1. Check for dynamic dispatch
      for (const dynRegex of this.DYNAMIC_DISPATCH_PATTERNS) {
        if (dynRegex.test(line)) {
          dynamicPatternsCount++;
          dynamicExplanations.push(
            `Line ${lineNum}: Dynamic method or reflection invocation detected: '${line.trim()}'`
          );
        }
      }

      // 2. Check for static SDK calls
      // Match patterns like s3.getObject(...) or client.sendMessage(...)
      const methodCallRegex = /\b(?:client|s3|dynamo|dynamodb|sqs|sns|secrets|kms|vault)\.([a-zA-Z0-9]+)\s*\(/g;
      let match: RegExpExecArray | null;
      while ((match = methodCallRegex.exec(line)) !== null) {
        const methodName = match[1];
        const iamAction = this.SDK_METHOD_TO_IAM[methodName];
        if (iamAction) {
          exercisedActions.add(iamAction);
          usageDetails.push({
            action: iamAction,
            service: iamAction.split(':')[0],
            callSignature: match[0],
            sourceFile: sourceFilePath,
            lineNumber: lineNum,
          });
        }
      }
    });

    const staticCallsCount = usageDetails.length;
    const totalPoints = staticCallsCount + dynamicPatternsCount * 3;
    const observabilityScore =
      totalPoints === 0
        ? 0.5
        : Math.max(0.1, Math.min(1.0, staticCallsCount / (staticCallsCount + dynamicPatternsCount * 3)));

    const observability: WorkloadObservabilityAnalysis = {
      staticallyAnalyzedCallsCount: staticCallsCount,
      dynamicPatternsDetectedCount: dynamicPatternsCount,
      observabilityScore: Number(observabilityScore.toFixed(2)),
      hasDynamicDispatch: dynamicPatternsCount > 0,
      dynamicPatternExplanations: dynamicExplanations,
    };

    return {
      exercisedActions: Array.from(exercisedActions),
      usageDetails,
      observability,
    };
  }
}
