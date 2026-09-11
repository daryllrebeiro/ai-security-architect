import { createRequire } from 'node:module';
import type { AttackPath } from '@ai-security-architect/core';
import type { SecurityGraphEngine } from '@ai-security-architect/graph';
import type {
  ComplianceReport,
  ComplianceFramework,
  ControlAssessment,
  FrameworkData,
  UnmappedFindingRecord,
} from './types.js';

const require = createRequire(import.meta.url);
const soc2Data: FrameworkData = require('./data/soc2.json');
const pciData: FrameworkData = require('./data/pci-dss-v4.json');
const nistData: FrameworkData = require('./data/nist-800-53.json');

export const COMPLIANCE_DISCLAIMER =
  'DISCLAIMER: This compliance assessment is strictly limited to automated architectural and code-level technical configurations observable by static graph analysis. It provides NO visibility into physical facility security, employee screening, human operational workflows, or administrative controls. It does NOT constitute a formal regulatory audit or certification.';

export class ComplianceEngine {
  private readonly frameworks: Map<string, FrameworkData> = new Map();

  constructor() {
    this.registerFramework(soc2Data);
    this.registerFramework(pciData);
    this.registerFramework(nistData);
  }

  public registerFramework(data: FrameworkData): void {
    this.frameworks.set(data.framework, data);
  }

  public evaluateCompliance(
    graph: SecurityGraphEngine,
    paths: AttackPath[],
    targetFrameworks?: ComplianceFramework[]
  ): ComplianceReport {
    const allFindings = graph.getAllFindings();
    const mappedFindingIds = new Set<string>();

    const frameworksToEvaluate = targetFrameworks
      ? Array.from(this.frameworks.values()).filter((f) => targetFrameworks.includes(f.framework))
      : Array.from(this.frameworks.values());

    const assessments: ControlAssessment[] = [];

    for (const fw of frameworksToEvaluate) {
      for (const ctrl of fw.controls) {
        if (!ctrl.observableByTool) {
          assessments.push({
            framework: fw.framework,
            controlId: ctrl.controlId,
            title: ctrl.title,
            description: ctrl.description,
            partition: 'NOT_OBSERVABLE_BY_TOOL',
            observableByTool: false,
            mappingRationale: ctrl.mappingRationale,
            violatingPathIds: [],
            violatingAssetIds: [],
            findingIds: [],
            evidence: [],
          });
          continue;
        }

        // Evaluate observable control against findings and attack paths
        const matchedFindingIds = new Set<string>();
        const matchedAssetIds = new Set<string>();
        const evidenceLines: string[] = [];

        if (ctrl.findingCategories && ctrl.findingCategories.length > 0) {
          const relevantFindings = allFindings.filter((f) =>
            ctrl.findingCategories!.includes(f.category)
          );
          for (const f of relevantFindings) {
            matchedFindingIds.add(f.id);
            mappedFindingIds.add(f.id);
            matchedAssetIds.add(f.assetId);
            evidenceLines.push(`Finding ${f.id} (${f.category}): ${f.title}`);
          }
        }

        // Evaluate attack path patterns if defined
        const violatingPathIds: string[] = [];
        if (ctrl.attackPathPattern) {
          for (const p of paths) {
            let matchesPattern = false;
            const entryNode = graph.getNode(p.entryAssetId);
            const targetNode = graph.getNode(p.targetAssetId);

            if (ctrl.attackPathPattern === 'INTERNET_INGRESS_TO_INTERNAL') {
              const isEntryPublic = entryNode?.asset.isPublic || entryNode?.asset.type === 'INTERNET';
              matchesPattern = Boolean(isEntryPublic && targetNode?.asset.isSensitiveData);
            } else if (ctrl.attackPathPattern === 'DIRECT_INTERNET_TO_CROWN_JEWEL') {
              const isEntryPublic = entryNode?.asset.isPublic || entryNode?.asset.type === 'INTERNET';
              const isTargetPaymentOrPii = (targetNode?.asset.tags ?? []).some((t) =>
                ['contains-pii', 'contains-payment-data', 'pci', 'cardholder'].some((k) =>
                  t.toLowerCase().includes(k)
                )
              );
              matchesPattern = Boolean(isEntryPublic && isTargetPaymentOrPii);
            } else if (ctrl.attackPathPattern === 'PERMISSIVE_IAM_OR_CREDENTIAL') {
              matchesPattern = p.steps.some(
                (s) =>
                  s.relationshipType === 'ASSUMES_ROLE' ||
                  s.relationshipType === 'CAN_ADMIN' ||
                  s.explanation.toLowerCase().includes('wildcard')
              );
            }

            if (matchesPattern) {
              violatingPathIds.push(p.id);
              matchedAssetIds.add(p.targetAssetId);
              evidenceLines.push(
                `Attack Path ${p.id} (${p.riskScore.totalRisk.toFixed(1)}/10.0): ${p.entryAssetId} ➔ ${p.targetAssetId}`
              );
              for (const step of p.steps) {
                if (step.findingId) {
                  matchedFindingIds.add(step.findingId);
                  mappedFindingIds.add(step.findingId);
                }
              }
            }
          }
        }

        const hasViolations = matchedFindingIds.size > 0 || violatingPathIds.length > 0;

        assessments.push({
          framework: fw.framework,
          controlId: ctrl.controlId,
          title: ctrl.title,
          description: ctrl.description,
          partition: hasViolations ? 'COVERED_WITH_FINDINGS' : 'COVERED_CLEAN',
          observableByTool: true,
          mappingRationale: ctrl.mappingRationale,
          violatingPathIds,
          violatingAssetIds: Array.from(matchedAssetIds),
          findingIds: Array.from(matchedFindingIds),
          evidence: evidenceLines,
        });
      }
    }

    // Determine unmapped findings
    const unmappedFindings: UnmappedFindingRecord[] = allFindings
      .filter((f) => !mappedFindingIds.has(f.id))
      .map((f) => ({
        findingId: f.id,
        category: f.category,
        title: f.title,
        severity: f.severity,
        assetId: f.assetId,
      }));

    const coveredCleanCount = assessments.filter((a) => a.partition === 'COVERED_CLEAN').length;
    const coveredWithFindingsCount = assessments.filter(
      (a) => a.partition === 'COVERED_WITH_FINDINGS'
    ).length;
    const notObservableCount = assessments.filter(
      (a) => a.partition === 'NOT_OBSERVABLE_BY_TOOL'
    ).length;

    return {
      tenantId: graph.tenantId,
      generatedAt: new Date().toISOString(),
      frameworks: frameworksToEvaluate.map((f) => f.framework),
      summary: {
        totalFrameworkControls: assessments.length,
        totalControls: assessments.length,
        coveredCleanCount,
        coveredWithFindingsCount,
        notObservableCount,
        unmappedFindingsCount: unmappedFindings.length,
      },
      controls: assessments,
      unmappedFindings,
      disclaimer: COMPLIANCE_DISCLAIMER,
    };
  }

  public formatMarkdownReport(report: ComplianceReport): string {
    const lines: string[] = [
      `# 🛡️ Architecture & Infrastructure Compliance Posture Report`,
      `**Tenant:** \`${report.tenantId}\` | **Generated At:** ${report.generatedAt}`,
      `**Frameworks:** ${report.frameworks.join(', ')}`,
      ``,
      `> ⚠️ **Scope & Honesty Notice**: ${report.disclaimer}`,
      ``,
      `## 📊 Control Coverage Partition Breakdown`,
      `| Coverage Partition | Count | Description |`,
      `| :--- | :--- | :--- |`,
      `| 🟢 **Covered — Currently Clean** | **${report.summary.coveredCleanCount}** | Technical controls observable by tool with zero open findings or paths. |`,
      `| 🔴 **Covered — Open Findings** | **${report.summary.coveredWithFindingsCount}** | Observable technical controls actively violated by architecture/findings. |`,
      `| ⚪ **Not Observable by This Tool** | **${report.summary.notObservableCount}** | Physical, HR, or organizational controls outside static graph visibility. |`,
      `| ⚠️ **Unmapped Findings** | **${report.summary.unmappedFindingsCount}** | Scan findings not correlated with any control in the selected frameworks. |`,
      ``,
    ];

    // Partition 1: Covered Clean
    const cleanControls = report.controls.filter((c) => c.partition === 'COVERED_CLEAN');
    if (cleanControls.length > 0) {
      lines.push(`### 🟢 1. Covered Controls — Currently Clean`);
      lines.push(`| Framework | Control ID | Title | Rationale |`);
      lines.push(`| :--- | :--- | :--- | :--- |`);
      for (const c of cleanControls) {
        lines.push(`| ${c.framework} | \`${c.controlId}\` | ${c.title} | ${c.mappingRationale} |`);
      }
      lines.push(``);
    }

    // Partition 2: Covered with Findings
    const findingControls = report.controls.filter((c) => c.partition === 'COVERED_WITH_FINDINGS');
    if (findingControls.length > 0) {
      lines.push(`### 🔴 2. Covered Controls — Open Findings`);
      lines.push(`| Framework | Control ID | Title | Violating Paths | Findings |`);
      lines.push(`| :--- | :--- | :--- | :--- | :--- |`);
      for (const c of findingControls) {
        const pathsStr = c.violatingPathIds.length > 0 ? c.violatingPathIds.join(', ') : 'Direct finding';
        const findingsStr = c.findingIds.length > 0 ? c.findingIds.join(', ') : 'None';
        lines.push(`| ${c.framework} | \`${c.controlId}\` | ${c.title} | \`${pathsStr}\` | \`${findingsStr}\` |`);
      }
      lines.push(``);
    }

    // Partition 3: Not Observable
    const notObsControls = report.controls.filter((c) => c.partition === 'NOT_OBSERVABLE_BY_TOOL');
    if (notObsControls.length > 0) {
      lines.push(`### ⚪ 3. Controls Not Observable by This Tool`);
      lines.push(`| Framework | Control ID | Title | Boundary Note |`);
      lines.push(`| :--- | :--- | :--- | :--- |`);
      for (const c of notObsControls) {
        lines.push(`| ${c.framework} | \`${c.controlId}\` | ${c.title} | ${c.mappingRationale} |`);
      }
      lines.push(``);
    }

    // Partition 4: Unmapped Findings
    if (report.unmappedFindings.length > 0) {
      lines.push(`### ⚠️ 4. Unmapped Scan Findings`);
      lines.push(`The following findings were detected during the scan but have no defined mapping in the evaluated frameworks:`);
      lines.push(`| Finding ID | Category | Title | Severity | Asset ID |`);
      lines.push(`| :--- | :--- | :--- | :--- | :--- |`);
      for (const u of report.unmappedFindings) {
        lines.push(`| \`${u.findingId}\` | \`${u.category}\` | ${u.title} | ${u.severity} | \`${u.assetId}\` |`);
      }
      lines.push(``);
    }

    return lines.join('\n');
  }
}
