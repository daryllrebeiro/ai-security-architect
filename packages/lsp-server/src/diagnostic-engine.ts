import { Diagnostic, DiagnosticSeverity } from 'vscode-languageserver';
import type { EphemeralWorkspace } from '@ai-security-architect/ingestion';
import { DiscoveryEngine } from '@ai-security-architect/discovery';
import { AnalyzerRunner } from '@ai-security-architect/analyzers';
import { DeterministicEntityResolver, EntityResolver } from '@ai-security-architect/graph';
import { AttackPathEngine, MinCutOptimizer } from '@ai-security-architect/attackpath';
import type { DocumentAnalysisResult, LspServerConfig } from './types.js';

export class DiagnosticEngine {
  private readonly config: LspServerConfig;
  private readonly discoveryEngine: DiscoveryEngine;
  private readonly analyzerRunner: AnalyzerRunner;
  private readonly entityResolver: DeterministicEntityResolver;
  private readonly attackPathEngine: AttackPathEngine;
  private readonly minCutOptimizer: MinCutOptimizer;

  constructor(config: LspServerConfig = {}) {
    this.config = {
      tenantId: config.tenantId ?? 'default-tenant',
      repository: config.repository ?? 'current-repo',
      offlineMode: config.offlineMode ?? false,
      ...config,
    };

    this.discoveryEngine = new DiscoveryEngine();
    this.analyzerRunner = new AnalyzerRunner();
    this.entityResolver = new EntityResolver();
    this.attackPathEngine = new AttackPathEngine();
    this.minCutOptimizer = new MinCutOptimizer();
  }

  /**
   * Performs real-time incremental analysis on a document within the given workspace.
   */
  public async analyzeDocument(
    workspace: EphemeralWorkspace,
    filePath: string,
    uri: string
  ): Promise<DocumentAnalysisResult> {
    const startTime = performance.now();
    const tenantId = this.config.tenantId!;
    const repository = this.config.repository!;

    // 1. Run incremental discovery
    const discovery = await this.discoveryEngine.discover({
      tenantId,
      repository,
      workspace,
    });

    // 2. Run AST and semantic analyzers
    const analysis = await this.analyzerRunner.runAnalyzers({
      tenantId,
      repository,
      workspace,
      discoveredAssets: discovery.assets,
    });

    // 3. Resolve Security Graph
    const graph = this.entityResolver.resolve({
      tenantId,
      assets: discovery.assets,
      relationships: discovery.relationships,
      findings: analysis.findings,
      evidence: [...discovery.evidence, ...analysis.evidence],
    });

    // 4. Analyze Attack Paths & Min-Cut Choke Points
    const attackPaths = this.attackPathEngine.analyzePaths(graph);
    this.minCutOptimizer.findOptimalChokePoints(graph, attackPaths);

    // 5. Correlate attack paths & findings to filePath
    const normalizedTarget = filePath.replace(/\\/g, '/');
    const diagnostics: Diagnostic[] = [];

    // Map critical attack paths reaching sensitive assets
    for (const path of attackPaths) {
      // Find if any step or choke point in the path references this file
      const relevantEvidence = analysis.evidence.filter((ev) => {
        const evPath = ev.filePath.replace(/\\/g, '/');
        return evPath.endsWith(normalizedTarget) || normalizedTarget.endsWith(evPath);
      });

      // If attack path involves this file or its findings
      const targetNode = graph.getNode(path.targetAssetId);
      const targetName = targetNode?.asset.name || path.targetAssetId;
      const chokePoint = path.recommendedChokePoint;

      if (relevantEvidence.length > 0) {
        for (const ev of relevantEvidence) {
          const isCritical = path.riskScore.totalRisk >= 8.0;
          diagnostics.push({
            severity: isCritical ? DiagnosticSeverity.Error : DiagnosticSeverity.Warning,
            range: {
              start: { line: Math.max(0, ev.lineStart - 1), character: 0 },
              end: { line: Math.max(1, ev.lineEnd), character: 0 },
            },
            message: `🚨 [Security Architect] Active Exploit Chain reaching crown jewel "${targetName}" (Risk: ${path.riskScore.totalRisk.toFixed(1)}/10.0)\n🎯 Optimal Min-Cut Choke Point: ${chokePoint?.actionDescription || 'Remediate vulnerability at this step'}`,
            source: 'ai-security-architect',
            code: path.id,
          });
        }
      }
    }

    // Map standalone findings in this file not already surfaced in paths
    const fileFindings = analysis.findings.filter((f) => {
      const ev = analysis.evidence.find((e) => e.id === f.evidence.id);
      if (!ev) return false;
      const evPath = ev.filePath.replace(/\\/g, '/');
      return evPath.endsWith(normalizedTarget) || normalizedTarget.endsWith(evPath);
    });

    for (const f of fileFindings) {
      // If finding already covered by path diagnostic at same line, skip duplicate
      const lineStart = Math.max(0, f.evidence.lineStart - 1);
      const alreadyCovered = diagnostics.some((d) => d.range.start.line === lineStart && d.code?.toString().startsWith('path-'));
      if (!alreadyCovered) {
        diagnostics.push({
          severity: f.severity === 'CRITICAL' ? DiagnosticSeverity.Error : DiagnosticSeverity.Warning,
          range: {
            start: { line: lineStart, character: 0 },
            end: { line: Math.max(1, f.evidence.lineEnd), character: 0 },
          },
          message: `⚠️ [${f.category}] ${f.title}: ${f.description}`,
          source: 'ai-security-architect',
          code: f.ruleId,
        });
      }
    }

    const durationMs = performance.now() - startTime;

    return {
      uri,
      filePath,
      diagnostics,
      attackPathsCount: attackPaths.length,
      criticalFindingsCount: analysis.findings.filter((f) => f.severity === 'CRITICAL').length,
      durationMs,
    };
  }
}
