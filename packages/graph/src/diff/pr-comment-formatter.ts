import type { PathDiffResult } from './path-diff-engine.js';

export class PrCommentFormatter {
  public format(diffResult: PathDiffResult, options: { baseRef?: string; headRef?: string } = {}): string {
    const { summary, introduced, closed, severityChanged } = diffResult;
    const baseLabel = options.baseRef ?? 'base';
    const headLabel = options.headRef ?? 'head';

    let md = `## 🛡️ AI Security Architect — Attack Path Diff Analysis\n\n`;
    md += `Comparing **\`${baseLabel}\`** ➔ **\`${headLabel}\`**\n\n`;

    // High level summary badges / metrics
    const statusIcon = introduced.length > 0 ? '🚨 **REGRESSION DETECTED**' : '✅ **NO NEW ATTACK PATHS**';
    md += `${statusIcon}\n\n`;

    md += `| Metric | Count |\n`;
    md += `| :--- | :--- |\n`;
    md += `| 🚨 **Newly Introduced Paths** | **${summary.introducedCount}** |\n`;
    md += `| 🛡️ **Closed Paths (Remediated)** | **${summary.closedRemediatedCount}** |\n`;
    md += `| 🗑️ **Closed Paths (Asset Removed)** | **${summary.closedAssetRemovedCount}** |\n`;
    md += `| ⚡ **Severity / Risk Changed** | **${summary.severityChangedCount}** |\n`;
    md += `| ⏸️ **Unchanged Paths** | **${summary.unchangedCount}** |\n\n`;

    // Introduced details
    if (introduced.length > 0) {
      md += `### 🚨 Newly Introduced Attack Paths\n\n`;
      md += `| Path ID | Risk | Entrypoint | Target Crown Jewel | Fingerprint |\n`;
      md += `| :--- | :--- | :--- | :--- | :--- |\n`;
      for (const item of introduced) {
        md += `| \`${item.path.id}\` | **${item.path.riskScore.totalRisk.toFixed(1)}/10.0** | \`${item.path.entryAssetId}\` | \`${item.path.targetAssetId}\` | \`${item.fingerprint}\` |\n`;
      }
      md += `\n`;
    }

    // Severity changed details
    if (severityChanged.length > 0) {
      md += `### ⚡ Severity Changed Paths\n\n`;
      md += `| Fingerprint | Base Risk | Head Risk | Delta | Target |\n`;
      md += `| :--- | :--- | :--- | :--- | :--- |\n`;
      for (const sc of severityChanged) {
        const deltaStr = sc.delta > 0 ? `+${sc.delta.toFixed(1)}` : `${sc.delta.toFixed(1)}`;
        md += `| \`${sc.fingerprint}\` | ${sc.baseRiskScore.toFixed(1)} | ${sc.headRiskScore.toFixed(1)} | **${deltaStr}** | \`${sc.headPath.targetAssetId}\` |\n`;
      }
      md += `\n`;
    }

    // Closed details
    if (closed.length > 0) {
      md += `### 🛡️ Closed Attack Paths\n\n`;
      md += `| Fingerprint | Target | Closure Reason |\n`;
      md += `| :--- | :--- | :--- |\n`;
      for (const cl of closed) {
        const reasonTag = cl.closureReason === 'remediated' ? '✅ Remediated' : cl.closureReason === 'asset-removed' ? '🗑️ Asset Removed' : '❓ Unknown';
        md += `| \`${cl.fingerprint}\` | \`${cl.path.targetAssetId}\` | ${reasonTag} |\n`;
      }
      md += `\n`;
    }

    md += `> *Automated PR comment by AI Security Architect*\n`;

    return md;
  }
}
