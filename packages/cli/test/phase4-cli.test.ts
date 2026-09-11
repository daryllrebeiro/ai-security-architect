import * as path from 'node:path';
import * as fs from 'node:fs/promises';
import { describe, it, expect, beforeAll } from 'vitest';
import { executeCompliance } from '../src/commands/compliance.js';
import { executeFair } from '../src/commands/fair.js';
import { executeRunbook } from '../src/commands/runbook.js';
import { executeQuery } from '../src/commands/query.js';
import { executeSimulate } from '../src/commands/simulate.js';
import { executePolicy } from '../src/commands/policy.js';
import { executeDashboard } from '../src/commands/dashboard.js';
import { executeDiff } from '../src/commands/diff.js';
import { executeFederate } from '../src/commands/federate.js';

describe('Phase 4 — Enterprise Governance, Risk Quantification & Operations CLI Integration', () => {
  const fixturePath = path.resolve('fixtures/001-ssrf-iam-s3');
  const tempOutputDir = path.resolve('.sec-arch/test-output');

  beforeAll(async () => {
    await fs.mkdir(tempOutputDir, { recursive: true });
  });

  it('sec-arch compliance: evaluates regulatory framework controls and outputs markdown report', async () => {
    const reportPath = path.join(tempOutputDir, 'compliance-report.md');
    const report = await executeCompliance({
      path: fixturePath,
      frameworks: ['SOC2', 'PCI-DSS', 'ISO27001'],
      format: 'markdown',
      outputFile: reportPath,
    });

    expect(report).toBeDefined();
    expect(report.summary.totalControls).toBeGreaterThan(0);
    expect(report.frameworks).toContain('SOC2');
    expect(report.frameworks).toContain('PCI-DSS');
    expect(report.disclaimer).toContain('DISCLAIMER');

    const fileContent = await fs.readFile(reportPath, 'utf-8');
    expect(fileContent).toContain('Compliance Posture Report');
    expect(fileContent).toContain('SOC2');
  });

  it('sec-arch fair: quantifies financial risk and calculates Annualized Loss Expectancy (ALE)', async () => {
    const fairPath = path.join(tempOutputDir, 'fair-report.json');
    const report = await executeFair({
      path: fixturePath,
      currency: 'USD',
      format: 'json',
      outputFile: fairPath,
    });

    expect(report).toBeDefined();
    expect(report.totalAnnualizedLossExpectancy).toBeGreaterThan(0);
    expect(report.maximumSingleEventLoss).toBeGreaterThan(0);
    expect(report.currency).toBe('USD');
    expect(report.paths.length).toBeGreaterThan(0);

    const firstExp = report.paths[0];
    expect(firstExp.threatEventFrequency).toBeGreaterThan(0);
    expect(firstExp.singleLossExpectancy).toBeGreaterThan(0);
    expect(firstExp.annualizedLossExpectancy).toBeGreaterThan(0);

    const fileContent = await fs.readFile(fairPath, 'utf-8');
    expect(JSON.parse(fileContent).totalAnnualizedLossExpectancy).toBe(report.totalAnnualizedLossExpectancy);
  });

  it('sec-arch runbook: generates step-by-step incident response playbook with rollback commands', async () => {
    const runbookFile = path.join(tempOutputDir, 'runbook.md');
    const playbook = await executeRunbook({
      path: fixturePath,
      outputFile: runbookFile,
    });

    expect(playbook).toBeDefined();
    expect(playbook.id).toContain('playbook-');
    expect(playbook.severity).toBe('CRITICAL');
    expect(playbook.preFlightChecks.length).toBeGreaterThan(0);
    expect(playbook.executionSteps.length).toBeGreaterThan(0);
    expect(playbook.rollbackSteps.length).toBeGreaterThan(0);
    expect(playbook.postVerificationQuery).toContain('sec-arch scan');

    const fileContent = await fs.readFile(runbookFile, 'utf-8');
    expect(fileContent).toContain('## 1. Pre-Flight Verification Checks');
    expect(fileContent).toContain('## 2. Step-by-Step Remediation Execution');
    expect(fileContent).toContain('## 3. Rollback Procedure');
  });

  it('sec-arch query: executes natural language query over security graph with grounded evidence', async () => {
    const result = await executeQuery({
      path: fixturePath,
      prompt: 'Which S3 buckets are exposed to the public internet?',
    });

    expect(result).toBeDefined();
    expect(result.query).toBe('Which S3 buckets are exposed to the public internet?');
    expect(result.totalPathsFound).toBeGreaterThan(0);
    expect(result.groundedAnswer).toBeDefined();
    expect(result.matchedPaths.length).toBeGreaterThan(0);
  });

  it('sec-arch simulate: simulates Purple Team lateral movement and forward blast radius', async () => {
    const result = await executeSimulate({
      path: fixturePath,
      assumedBreachNode: 'asset-k8s-pod-order-service',
    });

    expect(result).toBeDefined();
    expect(result.breachedAsset.id).toBe('asset-k8s-pod-order-service');
    expect(result.blastRadiusPaths.length).toBeGreaterThan(0);
    expect(result.reachableCrownJewels.some((c) => c.name.includes('customer-pii'))).toBe(true);
    expect(result.upstreamEntrypointPaths.length).toBeGreaterThan(0);
  });

  it('sec-arch policy: evaluates policy-as-code security budget limits', async () => {
    const evaluation = await executePolicy({
      path: fixturePath,
      failOnBreach: false,
    });

    expect(evaluation).toBeDefined();
    // On first adoption with grandfatherExisting: true, existing debt is grandfathered
    expect(evaluation.summary.grandfatheredCount).toBeGreaterThan(0);
    expect(evaluation.passed).toBe(true);
  });

  it('sec-arch dashboard: generates historical risk trend & MTTR HTML report', async () => {
    const dashboardHtml = path.join(tempOutputDir, 'dashboard.html');
    const summary = await executeDashboard({
      path: fixturePath,
      outputFile: dashboardHtml,
    });

    expect(summary).toBeDefined();
    expect(summary.totalScans).toBeGreaterThan(0);
    expect(summary.currentTotalPaths).toBeGreaterThan(0);

    const htmlContent = await fs.readFile(dashboardHtml, 'utf-8');
    expect(htmlContent).toContain('<!DOCTYPE html>');
    expect(htmlContent).toContain('Security Risk Trend & MTTR Dashboard');
    expect(htmlContent).toContain(summary.repository);
  });

  it('sec-arch diff: computes attack path delta and generates PR comment markdown', async () => {
    const diffReport = path.join(tempOutputDir, 'diff-report.md');
    const result = await executeDiff({
      basePath: fixturePath,
      headPath: fixturePath,
      format: 'markdown',
      prComment: true,
      outputFile: diffReport,
    });

    expect(result).toBeDefined();
    expect(result.summary).toBeDefined();
    expect(result.summary.introducedCount).toBe(0); // Identical baseline and head
    expect(result.summary.unchangedCount).toBeGreaterThan(0);

    const content = await fs.readFile(diffReport, 'utf-8');
    expect(content).toContain('Attack Path Diff Analysis');
    expect(content).toContain('Unchanged Paths');
  });

  it('sec-arch federate: merges multi-repo graphs from federation manifest and exports unified graph', async () => {
    const manifestFile = path.join(tempOutputDir, 'test-manifest.json');
    const federatedOutputFile = path.join(tempOutputDir, 'federated-graph.json');

    const manifestContent = {
      tenantId: 'tenant-fed-cli',
      repositories: [
        { repository: 'org/service-alpha', path: fixturePath },
        { repository: 'org/service-beta', path: fixturePath },
      ],
    };

    await fs.writeFile(manifestFile, JSON.stringify(manifestContent, null, 2), 'utf-8');

    const result = await executeFederate({
      manifestPath: manifestFile,
      outputFile: federatedOutputFile,
    });

    expect(result).toBeDefined();
    expect(result.federatedRepos).toContain('org/service-alpha');
    expect(result.federatedRepos).toContain('org/service-beta');
    expect(result.totalNodes).toBeGreaterThan(0);

    const exported = JSON.parse(await fs.readFile(federatedOutputFile, 'utf-8'));
    expect(exported.tenantId).toBe('tenant-fed-cli');
    expect(exported.nodes.length).toBe(result.totalNodes);
  });
});
