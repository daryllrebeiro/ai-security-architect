import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { ScanHistoryStore } from '@ai-security-architect/graph';
import { HistoricalDashboardEngine, type DashboardSummary } from '@ai-security-architect/dashboard';
import { executeScan } from './scan.js';
import type { CliDashboardOptions } from '../types.js';

export async function executeDashboard(options: CliDashboardOptions): Promise<DashboardSummary> {
  const scanResult = await executeScan({
    path: options.path,
    tenantId: options.tenantId,
    silent: true,
  });

  const dbDir = path.resolve('.sec-arch');
  await fs.mkdir(dbDir, { recursive: true });
  const dbPath = path.join(dbDir, 'history.db');

  const store = new ScanHistoryStore(dbPath);
  const scanId = `scan-${Date.now()}`;
  const commitSha = process.env.GITHUB_SHA || 'local-scan';
  const timestamp = new Date().toISOString();

  // Record current scan in persistent historical store
  store.recordScan(
    scanId,
    scanResult.tenantId,
    scanResult.repository,
    commitSha,
    scanResult.attackPaths,
    timestamp
  );

  const engine = new HistoricalDashboardEngine(store);
  const summary = engine.calculateDashboardSummary(scanResult.repository);
  const html = engine.renderHtmlDashboard(summary);

  const outPath = options.outputFile || path.join(dbDir, 'dashboard.html');
  await fs.writeFile(outPath, html, 'utf-8');

  console.log(`\n================================================================================`);
  console.log(`  HISTORICAL RISK TREND & MTTR DASHBOARD`);
  console.log(`================================================================================`);
  console.log(`  Repository:            ${summary.repository}`);
  console.log(`  Total Historical Scans:${summary.totalScans}`);
  console.log(`  Current Total Paths:   ${summary.currentTotalPaths} (${summary.currentCriticalPaths} Critical)`);
  console.log(`  MTTR (Mean Time):      ${summary.meanTimeToRemediationHours !== null ? `${summary.meanTimeToRemediationHours} hours` : 'N/A'}`);
  console.log(`  Remediated Paths:      ${summary.remediatedPathsCount}`);
  console.log(`  HTML Dashboard:        ${outPath}`);
  console.log(`================================================================================\n`);

  if (options.serve) {
    const port = options.port || 3000;
    const { url } = await engine.startLocalDashboardServer(summary, port);
    console.log(`[DASHBOARD] Local server active at ${url}`);
    console.log(`[DASHBOARD] Press Ctrl+C to terminate the dashboard server.`);
  }

  return summary;
}
