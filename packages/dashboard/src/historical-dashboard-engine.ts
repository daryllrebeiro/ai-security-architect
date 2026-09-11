import * as http from 'node:http';
import type { ScanHistoryStore } from '@ai-security-architect/graph';
import type { DashboardSummary, MttrMetric, RiskTrendPoint } from './types.js';

export class HistoricalDashboardEngine {
  constructor(private readonly store: ScanHistoryStore) {}

  public async startLocalDashboardServer(
    summary: DashboardSummary,
    port = 3000
  ): Promise<{ server: http.Server; url: string; close: () => Promise<void> }> {
    const html = this.renderHtmlDashboard(summary);
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
    });

    return new Promise((resolve) => {
      server.listen(port, () => {
        const address = server.address();
        const actualPort = typeof address === 'object' && address ? address.port : port;
        const url = `http://localhost:${actualPort}`;
        resolve({
          server,
          url,
          close: () =>
            new Promise<void>((resClose, rejClose) => {
              server.close((err) => (err ? rejClose(err) : resClose()));
            }),
        });
      });
    });
  }

  public calculateDashboardSummary(repository: string): DashboardSummary {
    const scans = this.store.getAllScans(repository);

    if (scans.length === 0) {
      return {
        repository,
        tenantId: 'unknown',
        totalScans: 0,
        currentTotalPaths: 0,
        currentCriticalPaths: 0,
        meanTimeToRemediationHours: null,
        remediatedPathsCount: 0,
        assetRemovedCount: 0,
        riskTrendSeries: [],
        mttrDetails: [],
      };
    }

    const latestScan = scans[scans.length - 1];
    const closures = this.store.getClosures(repository);

    let assetRemovedCount = 0;
    const mttrDetails: MttrMetric[] = [];

    for (const closure of closures) {
      // CRITICAL CONSTRAINT: Exclude asset-removed from MTTR credit!
      if (closure.closureReason === 'asset-removed') {
        assetRemovedCount++;
        continue;
      }

      if (closure.closureReason === 'remediated') {
        const history = this.store.getPathsByFingerprint(closure.fingerprint);
        const introducedAt = history.length > 0 ? history[0].timestamp : closure.closedAt;

        const durationMs =
          new Date(closure.closedAt).getTime() - new Date(introducedAt).getTime();
        const durationHours =
          Math.max(0, Math.round((durationMs / (1000 * 3600)) * 10) / 10);

        mttrDetails.push({
          fingerprint: closure.fingerprint,
          introducedAt,
          closedAt: closure.closedAt,
          durationHours,
          closureReason: 'remediated',
          originAssetId: closure.originAssetId,
        });
      }
    }

    const meanTimeToRemediationHours =
      mttrDetails.length > 0
        ? Math.round(
            (mttrDetails.reduce((sum, m) => sum + m.durationHours, 0) / mttrDetails.length) * 10
          ) / 10
        : null;

    const riskTrendSeries: RiskTrendPoint[] = scans.map((s) => ({
      scanId: s.scanId,
      commitSha: s.commitSha,
      timestamp: s.timestamp,
      totalPaths: s.totalPaths,
      criticalPaths: s.criticalPaths,
      highPaths: s.highPaths,
      mediumPaths: s.mediumPaths,
      lowPaths: s.lowPaths,
    }));

    return {
      repository,
      tenantId: latestScan.tenantId,
      totalScans: scans.length,
      currentTotalPaths: latestScan.totalPaths,
      currentCriticalPaths: latestScan.criticalPaths,
      meanTimeToRemediationHours,
      remediatedPathsCount: mttrDetails.length,
      assetRemovedCount,
      riskTrendSeries,
      mttrDetails,
    };
  }

  public renderHtmlDashboard(summary: DashboardSummary): string {
    const mttrDisplay =
      summary.meanTimeToRemediationHours !== null
        ? `${summary.meanTimeToRemediationHours} hrs`
        : 'N/A';

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Security Risk Trend & MTTR Dashboard — ${summary.repository}</title>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --accent: #58a6ff;
      --danger: #f85149;
      --success: #3fb950;
      --warning: #d29922;
    }
    body {
      margin: 0;
      padding: 2rem;
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    .header { margin-bottom: 2rem; }
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1.5rem;
      margin-bottom: 2rem;
    }
    .kpi-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem;
    }
    .kpi-title { font-size: 0.85rem; color: #8b949e; text-transform: uppercase; margin-bottom: 0.5rem; }
    .kpi-value { font-size: 2rem; font-weight: bold; color: var(--text); }
    .kpi-desc { font-size: 0.75rem; color: #8b949e; margin-top: 0.25rem; }
    .trend-table {
      width: 100%;
      border-collapse: collapse;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
    }
    .trend-table th, .trend-table td {
      padding: 0.75rem 1rem;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }
    .trend-table th { background: #21262d; color: #8b949e; }
  </style>
</head>
<body>
  <div class="header">
    <h1>Security Risk Trend & MTTR Dashboard</h1>
    <p>Repository: <code>${summary.repository}</code> | Tenant: <code>${summary.tenantId}</code></p>
  </div>

  <div class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-title">Active Attack Paths</div>
      <div class="kpi-value">${summary.currentTotalPaths}</div>
      <div class="kpi-desc">Across latest scan</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">Critical Paths</div>
      <div class="kpi-value" style="color: var(--danger);">${summary.currentCriticalPaths}</div>
      <div class="kpi-desc">Requires immediate remediation</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">True Mean Time To Remediate (MTTR)</div>
      <div class="kpi-value" style="color: var(--success);">${mttrDisplay}</div>
      <div class="kpi-desc">Excludes asset removals</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">Genuine Remediations</div>
      <div class="kpi-value">${summary.remediatedPathsCount}</div>
      <div class="kpi-desc">${summary.assetRemovedCount} decommissioned</div>
    </div>
  </div>

  <h2>Scan History Time Series</h2>
  <table class="trend-table">
    <thead>
      <tr>
        <th>Scan ID</th>
        <th>Commit SHA</th>
        <th>Timestamp</th>
        <th>Total Paths</th>
        <th>Critical</th>
        <th>High</th>
        <th>Medium</th>
        <th>Low</th>
      </tr>
    </thead>
    <tbody>
      ${summary.riskTrendSeries
        .map(
          (s) => `
      <tr>
        <td><code>${s.scanId}</code></td>
        <td><code>${s.commitSha.substring(0, 8)}</code></td>
        <td>${s.timestamp}</td>
        <td><b>${s.totalPaths}</b></td>
        <td style="color: var(--danger);">${s.criticalPaths}</td>
        <td style="color: var(--warning);">${s.highPaths}</td>
        <td>${s.mediumPaths}</td>
        <td>${s.lowPaths}</td>
      </tr>`
        )
        .join('')}
    </tbody>
  </table>
</body>
</html>`;
  }
}
