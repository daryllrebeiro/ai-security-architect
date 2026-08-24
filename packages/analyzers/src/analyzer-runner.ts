import {
  FindingSchema,
  EvidenceSchema,
  type Finding,
  type Evidence,
} from '@ai-security-architect/core';
import type { AnalyzerContext, SecurityAnalyzer, AnalyzerResult } from './types.js';
import { SecretAnalyzer } from './analyzers/secret-analyzer.js';
import { SastCodeAnalyzer } from './analyzers/sast-code-analyzer.js';
import { IacTerraformAnalyzer } from './analyzers/iac-terraform-analyzer.js';
import { ScaDependencyAnalyzer } from './analyzers/sca-dependency-analyzer.js';

export class AnalyzerRunner {
  private readonly analyzers: SecurityAnalyzer[];

  constructor(analyzers?: SecurityAnalyzer[]) {
    this.analyzers = analyzers ?? [
      new SecretAnalyzer(),
      new SastCodeAnalyzer(),
      new IacTerraformAnalyzer(),
      new ScaDependencyAnalyzer(),
    ];
  }

  public async runAnalyzers(context: AnalyzerContext): Promise<AnalyzerResult> {
    const fileList = await context.workspace.listFilesSafe();

    const findingsMap = new Map<string, Finding>();
    const evidenceMap = new Map<string, Evidence>();

    for (const analyzer of this.analyzers) {
      const isSupported = await analyzer.supports(context.workspace, fileList);
      if (!isSupported) {
        continue;
      }

      try {
        const result = await analyzer.analyze(context, fileList);

        for (const finding of result.findings) {
          // Strict Zod validation
          FindingSchema.parse(finding);
          findingsMap.set(finding.id, finding);
        }

        for (const ev of result.evidence) {
          // Strict Zod validation
          EvidenceSchema.parse(ev);
          evidenceMap.set(ev.id, ev);
        }
      } catch (err: unknown) {
        console.warn(`[AnalyzerRunner] Analyzer "${analyzer.name}" failed: ${(err as Error).message}`);
      }
    }

    return {
      findings: Array.from(findingsMap.values()),
      evidence: Array.from(evidenceMap.values()),
    };
  }
}
