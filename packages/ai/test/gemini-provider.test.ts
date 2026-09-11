import { describe, it, expect, vi } from 'vitest';
import { GeminiLLMProvider } from '../src/providers/gemini-provider.js';
import { redactSensitiveData } from '../src/context-builder.js';

describe('GeminiLLMProvider', () => {
  it('successfully parses valid JSON response matching AIReasoningOutputSchema', async () => {
    const mockOutput = {
      summary: 'Critical attack path detected reaching customer PII',
      rootCauseAnalysis: 'Wildcard IAM policy combined with SSRF sink allows cloud privilege escalation.',
      businessImpact: 'Unauthorized data exfiltration of customer PII in production.',
      evidenceReferences: ['ev-01'],
      reasoningFailed: false,
      recommendedRemediation: {
        description: 'Constrain IAM policy in terraform/iam.tf to specific bucket.',
        targetChokePoint: 'iam_role -> s3_bucket',
        expectedRiskReductionPercentage: 100,
        engineeringEffort: 'LOW',
        patches: [
          {
            filePath: 'terraform/iam.tf',
            action: 'MODIFY',
            unifiedDiff: '--- a/terraform/iam.tf\n+++ b/terraform/iam.tf\n@@ -1,1 +1,1 @@\n-s3:*\n+s3:GetObject',
            description: 'Scope permissions',
          },
        ],
      },
      alternativeRemediations: [],
      confidence: 'VERY_HIGH',
    };

    const mockClient = {
      models: {
        generateContent: vi.fn().mockResolvedValue({
          text: JSON.stringify(mockOutput),
        }),
      },
    };

    const provider = new GeminiLLMProvider({ client: mockClient });
    const response = await provider.generateCompletion('test user prompt', 'test system prompt');
    const parsed = JSON.parse(response);

    expect(parsed.summary).toBe(mockOutput.summary);
    expect(parsed.reasoningFailed).toBe(false);
    expect(parsed.recommendedRemediation.patches.length).toBe(1);
    expect(mockClient.models.generateContent).toHaveBeenCalledTimes(1);
  });

  it('triggers repair retry when first attempt returns invalid schema, then succeeds on retry', async () => {
    const validOutput = {
      summary: 'Valid summary on second attempt',
      rootCauseAnalysis: 'Root cause',
      businessImpact: 'High business impact',
      evidenceReferences: [],
      reasoningFailed: false,
      recommendedRemediation: {
        description: 'Fix policy',
        targetChokePoint: 'a -> b',
        expectedRiskReductionPercentage: 100,
        engineeringEffort: 'LOW',
        patches: [],
      },
      alternativeRemediations: [],
      confidence: 'HIGH',
    };

    const mockClient = {
      models: {
        generateContent: vi
          .fn()
          .mockResolvedValueOnce({
            // Invalid schema (missing required fields)
            text: '{"some_unrecognized_key": 123}',
          })
          .mockResolvedValueOnce({
            // Valid response on retry
            text: JSON.stringify(validOutput),
          }),
      },
    };

    const provider = new GeminiLLMProvider({ client: mockClient, maxRetries: 2 });
    const response = await provider.generateCompletion('test prompt', 'test system prompt');
    const parsed = JSON.parse(response);

    expect(parsed.summary).toBe('Valid summary on second attempt');
    expect(mockClient.models.generateContent).toHaveBeenCalledTimes(2);
  });

  it('fails closed with reasoningFailed: true and empty patches when retries are exhausted', async () => {
    const mockClient = {
      models: {
        generateContent: vi.fn().mockResolvedValue({
          text: 'Totally unparseable non-json garbage response',
        }),
      },
    };

    const provider = new GeminiLLMProvider({ client: mockClient, maxRetries: 1 });
    const response = await provider.generateCompletion('test prompt', 'test system prompt');
    const parsed = JSON.parse(response);

    expect(parsed.reasoningFailed).toBe(true);
    expect(parsed.recommendedRemediation.patches).toEqual([]);
    expect(parsed.summary).toContain('failed schema verification');
    expect(mockClient.models.generateContent).toHaveBeenCalledTimes(2); // 1 initial + 1 retry
  });
});

describe('Extended Secret Redaction', () => {
  it('redacts JWT tokens', () => {
    const input = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jV_dummy_signature_sample';
    const result = redactSensitiveData(input);
    expect(result).not.toContain('eyJhbGciOi');
    expect(result).toContain('[REDACTED_JWT_TOKEN]');
  });

  it('redacts GCP Service Account private keys', () => {
    const input = '{\n  "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASC\\n-----END PRIVATE KEY-----\\n"\n}';
    const result = redactSensitiveData(input);
    expect(result).not.toContain('MIIEvgIBADAN');
    expect(result).toContain('[REDACTED_GCP_KEY]');
  });

  it('redacts Database URIs with credentials', () => {
    const input = 'DATABASE_URL="postgres://admin:supersecretpassword123@db.prod.internal:5432/finance"';
    const result = redactSensitiveData(input);
    expect(result).not.toContain('supersecretpassword123');
    expect(result).toContain('[REDACTED_DATABASE_URI]');
  });

  it('redacts Discord and Teams incoming webhooks', () => {
    const input = 'const url = "https://discord.com/api/webhooks/1234567890/token123";';
    const result = redactSensitiveData(input);
    expect(result).not.toContain('token123');
    expect(result).toContain('[REDACTED_WEBHOOK_URL]');
  });
});
