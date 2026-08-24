import {
  createEvidence,
  type Finding,
  type Evidence,
} from '@ai-security-architect/core';
import type { AnalyzerContext, SecurityAnalyzer, AnalyzerResult } from '../types.js';
import type { EphemeralWorkspace } from '@ai-security-architect/ingestion';

interface SecretRule {
  id: string;
  title: string;
  regex: RegExp;
  severity: 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
}

export class SecretAnalyzer implements SecurityAnalyzer {
  public readonly name = 'SecretAnalyzer';

  private readonly rules: SecretRule[] = [
    {
      id: 'SECRET-AWS-ACCESS-KEY',
      title: 'Hardcoded AWS Access Key ID',
      regex: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/,
      severity: 'HIGH',
      description: 'An AWS access key ID was discovered hardcoded in configuration or source code.',
    },
    {
      id: 'SECRET-PRIVATE-KEY',
      title: 'Unencrypted Private Key',
      regex: /-----BEGIN (?:RSA |OPENSSH |DSA |EC |PGP )?PRIVATE KEY-----/,
      severity: 'CRITICAL',
      description: 'An unencrypted private key was identified in plaintext.',
    },
    {
      id: 'SECRET-GITHUB-TOKEN',
      title: 'Hardcoded GitHub Personal Access Token',
      regex: /ghp_[a-zA-Z0-9]{36}/,
      severity: 'CRITICAL',
      description: 'A GitHub personal access token was discovered in the repository.',
    },
    {
      id: 'SECRET-GENERIC-PASSWORD',
      title: 'Hardcoded Database or Service Password',
      regex: /(?:password|passwd|pwd|db_pass)\s*[:=]\s*["']([^"'\s]{8,})["']/i,
      severity: 'MEDIUM',
      description: 'A plaintext password assignment was detected.',
    },
  ];

  public async supports(_workspace: EphemeralWorkspace, _fileList: string[]): Promise<boolean> {
    return true; // Secrets can exist in any repo
  }

  public async analyze(context: AnalyzerContext, fileList: string[]): Promise<AnalyzerResult> {
    const findings: Finding[] = [];
    const evidenceList: Evidence[] = [];

    const scannableFiles = fileList.filter(
      (f) =>
        !f.endsWith('.png') &&
        !f.endsWith('.jpg') &&
        !f.endsWith('.jar') &&
        !f.endsWith('.zip') &&
        !f.includes('package-lock.json')
    );

    for (const filePath of scannableFiles) {
      let content: string;
      try {
        content = await context.workspace.readSafeFile(filePath);
      } catch {
        continue;
      }

      const lines = content.split('\n');

      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex];

        for (const rule of this.rules) {
          const match = line.match(rule.regex);
          if (match) {
            const lineStart = lineIndex + 1;
            const lineEnd = lineStart;
            const snippet = line.trim();

            const evidence = createEvidence({
              id: `ev-secret-${filePath.replace(/[^a-zA-Z0-9]/g, '_')}-${lineStart}`,
              tenantId: context.tenantId,
              sourceType: 'SECRET_SCAN',
              repository: context.repository,
              filePath,
              lineStart,
              lineEnd,
              snippet,
              scanner: 'SecretAnalyzer',
            });
            evidenceList.push(evidence);

            // Match finding to asset if matching file
            const matchingAsset =
              context.discoveredAssets.find((a) => a.metadata.filePath === filePath) ||
              context.discoveredAssets.find((a) => a.type === 'SERVICE') ||
              context.discoveredAssets[0];

            findings.push({
              id: `finding-${rule.id.toLowerCase()}-${filePath.replace(/[^a-zA-Z0-9]/g, '_')}-${lineStart}`,
              tenantId: context.tenantId,
              assetId: matchingAsset?.id || 'asset-repository',
              category: 'SECRET_EXPOSURE',
              ruleId: rule.id,
              title: rule.title,
              description: rule.description,
              severity: rule.severity,
              confidence: 'HIGH',
              scanner: 'SecretAnalyzer',
              evidence,
              remediationRecommendation:
                'Remove the hardcoded secret immediately, rotate the exposed credential, and use a secret manager (AWS Secrets Manager / Vault).',
              metadata: { filePath, lineStart },
            });
          }
        }
      }
    }

    return { findings, evidence: evidenceList };
  }
}
