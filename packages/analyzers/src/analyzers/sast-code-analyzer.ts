import {
  createEvidence,
  type Finding,
  type Evidence,
} from '@ai-security-architect/core';
import type { AnalyzerContext, SecurityAnalyzer, AnalyzerResult } from '../types.js';
import type { EphemeralWorkspace } from '@ai-security-architect/ingestion';

export class SastCodeAnalyzer implements SecurityAnalyzer {
  public readonly name = 'SastCodeAnalyzer';

  public async supports(_workspace: EphemeralWorkspace, fileList: string[]): Promise<boolean> {
    return fileList.some((f) => f.endsWith('.java') || f.endsWith('.py') || f.endsWith('.ts') || f.endsWith('.js'));
  }

  public async analyze(context: AnalyzerContext, fileList: string[]): Promise<AnalyzerResult> {
    const findings: Finding[] = [];
    const evidenceList: Evidence[] = [];

    const javaFiles = fileList.filter((f) => f.endsWith('.java'));

    for (const filePath of javaFiles) {
      let content: string;
      try {
        content = await context.workspace.readSafeFile(filePath);
      } catch {
        continue;
      }

      const lines = content.split('\n');

      // Rule: SSRF via unvalidated HttpURLConnection / URL opening
      const ssrfRegex = /new\s+URL\s*\(\s*([a-zA-Z0-9_]+)\s*\)[\s\S]*?openConnection\(\)/;
      const ssrfMatch = content.match(ssrfRegex);

      if (ssrfMatch) {
        const matchIndex = content.indexOf(ssrfMatch[0]);
        const lineStart = content.substring(0, matchIndex).split('\n').length;
        const lineEnd = lineStart + ssrfMatch[0].split('\n').length;
        const snippet = lines.slice(Math.max(0, lineStart - 2), Math.min(lines.length, lineEnd + 3)).join('\n');

        const evidence = createEvidence({
          id: `ev-sast-ssrf-${filePath.replace(/[^a-zA-Z0-9]/g, '_')}-${lineStart}`,
          tenantId: context.tenantId,
          sourceType: 'SOURCE_CODE',
          repository: context.repository,
          filePath,
          lineStart,
          lineEnd,
          snippet,
          scanner: 'SastCodeAnalyzer',
        });
        evidenceList.push(evidence);

        // Find endpoint asset in this file
        const matchingEndpoint =
          context.discoveredAssets.find(
            (a) => a.type === 'ENDPOINT' && a.metadata.filePath === filePath
          ) ||
          context.discoveredAssets.find((a) => a.type === 'ENDPOINT') ||
          context.discoveredAssets.find((a) => a.type === 'SERVICE');

        findings.push({
          id: `finding-ssrf-${filePath.replace(/[^a-zA-Z0-9]/g, '_')}-${lineStart}`,
          tenantId: context.tenantId,
          assetId: matchingEndpoint?.id || 'asset-endpoint',
          category: 'SSRF',
          ruleId: 'SSRF-SPRING-URL-CONNECTION',
          title: 'Server-Side Request Forgery via Unvalidated Webhook URL',
          description:
            'The application receives a user-controllable URL and establishes an outbound HTTP connection without IP or domain allowlist validation. In cloud environments, this enables attackers to access the AWS Instance Metadata Service (IMDS at 169.254.169.254) and retrieve temporary IAM credentials.',
          severity: 'HIGH',
          confidence: 'HIGH',
          scanner: 'SastCodeAnalyzer',
          cwe: 'CWE-918',
          evidence,
          remediationRecommendation:
            'Implement an IP address and hostname allowlist. Block private IP ranges (RFC 1918) and link-local addresses (169.254.0.0/16). Enforce IMDSv2 on cloud instances.',
          metadata: { filePath, lineStart, lineEnd },
        });
      }

      // Rule: SQL Injection
      const sqliRegex = /Statement\.executeQuery\s*\(\s*["'].*?\+\s*[a-zA-Z0-9_]+/;
      if (sqliRegex.test(content)) {
        const lineMatch = lines.findIndex((l) => sqliRegex.test(l));
        const lineStart = lineMatch + 1;
        const snippet = lines[lineMatch];

        const evidence = createEvidence({
          id: `ev-sast-sqli-${filePath.replace(/[^a-zA-Z0-9]/g, '_')}-${lineStart}`,
          tenantId: context.tenantId,
          sourceType: 'SOURCE_CODE',
          repository: context.repository,
          filePath,
          lineStart,
          lineEnd: lineStart,
          snippet,
          scanner: 'SastCodeAnalyzer',
        });
        evidenceList.push(evidence);

        findings.push({
          id: `finding-sqli-${filePath.replace(/[^a-zA-Z0-9]/g, '_')}-${lineStart}`,
          tenantId: context.tenantId,
          assetId: context.discoveredAssets.find((a) => a.type === 'SERVICE')?.id || 'asset-service',
          category: 'SQL_INJECTION',
          ruleId: 'SQLI-RAW-CONCATENATION',
          title: 'SQL Injection via Dynamic String Concatenation',
          description: 'Untrusted user parameter concatenated directly into raw SQL query.',
          severity: 'CRITICAL',
          confidence: 'HIGH',
          scanner: 'SastCodeAnalyzer',
          cwe: 'CWE-89',
          evidence,
          remediationRecommendation: 'Use parameterized queries / prepared statements instead of string concatenation.',
          metadata: { filePath, lineStart },
        });
      }
    }

    return { findings, evidence: evidenceList };
  }
}
