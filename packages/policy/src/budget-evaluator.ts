import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import type { AttackPath } from '@ai-security-architect/core';
import type { PathDiffResult, SecurityGraphEngine } from '@ai-security-architect/graph';
import {
  SecurityBudgetPolicySchema,
  type SecurityBudgetPolicy,
  type BudgetViolation,
  type BudgetEvaluationResult,
} from './types.js';

export interface BaselineSnapshot {
  tenantId: string;
  snapshottedAt: string;
  paths: Array<{
    id: string;
    fingerprint: string;
    riskScore: number;
    targetAssetId: string;
  }>;
}

export class BudgetEvaluator {
  /**
   * Evaluates attack paths from a PR diff against configured policy-as-code budgets.
   */
  public evaluateDiff(
    diff: PathDiffResult,
    policyConfig: Partial<SecurityBudgetPolicy> = {}
  ): BudgetEvaluationResult {
    const policy = SecurityBudgetPolicySchema.parse(policyConfig);
    const violations: BudgetViolation[] = [];
    const grandfatheredPaths: AttackPath[] = [];

    // 1. Max new paths per PR check
    if (diff.introduced.length > policy.maxNewPathsPerPR) {
      violations.push({
        rule: 'maxNewPathsPerPR',
        message: `PR introduced ${diff.introduced.length} new attack paths (policy budget limit: ${policy.maxNewPathsPerPR})`,
        severity: 'HIGH',
        actualValue: diff.introduced.length,
        limitValue: policy.maxNewPathsPerPR,
        pathId: diff.introduced.map((p) => p.path.id).join(', '),
      });
    }

    // 2. Separate paths into active evaluation set vs grandfathered set
    const pathsToEvaluate: AttackPath[] = [];

    for (const item of diff.introduced) {
      pathsToEvaluate.push(item.path);
    }

    if (policy.grandfatherExisting) {
      // Existing paths that got worse in severity are NOT grandfathered
      for (const item of diff.severityChanged) {
        if (item.delta > 0) {
          pathsToEvaluate.push(item.headPath);
        } else {
          grandfatheredPaths.push(item.headPath);
        }
      }
      for (const item of diff.unchanged) {
        grandfatheredPaths.push(item.path);
      }
    } else {
      // Strict mode: evaluate all paths currently present in the architecture
      for (const item of diff.severityChanged) {
        pathsToEvaluate.push(item.headPath);
      }
      for (const item of diff.unchanged) {
        pathsToEvaluate.push(item.path);
      }
    }

    // 3. Evaluate each path in the active set
    this.evaluatePathList(pathsToEvaluate, policy, violations);

    const criticalViolations = violations.filter((v) => v.severity === 'CRITICAL').length;

    return {
      passed: violations.length === 0,
      policy,
      violations,
      grandfatheredPaths,
      diffEvaluated: true,
      newPathsEvaluationStatus: 'EVALUATED',
      summary: {
        totalViolations: violations.length,
        criticalViolations,
        grandfatheredCount: grandfatheredPaths.length,
        totalEvaluated: pathsToEvaluate.length,
      },
    };
  }

  /**
   * Standalone evaluation of current paths with grandfathering baseline support.
   * On first run when baseline file does not exist, it creates the baseline snapshot and passes without failing on grandfathered debt.
   */
  public async evaluateWithBaseline(
    currentPaths: AttackPath[],
    graph: SecurityGraphEngine,
    policyConfig: Partial<SecurityBudgetPolicy> = {},
    options: { baselineFilePath?: string } = {}
  ): Promise<BudgetEvaluationResult> {
    const policy = SecurityBudgetPolicySchema.parse(policyConfig);
    const violations: BudgetViolation[] = [];
    const grandfatheredPaths: AttackPath[] = [];
    const pathsToEvaluate: AttackPath[] = [];

    const baselineFile = options.baselineFilePath || path.resolve('.sec-arch/policy-baseline.json');
    let baseline: BaselineSnapshot | null = null;

    try {
      const raw = await fs.readFile(baselineFile, 'utf-8');
      baseline = JSON.parse(raw) as BaselineSnapshot;
    } catch {
      // Baseline does not exist yet -> First adoption run
      baseline = null;
    }

    if (policy.grandfatherExisting && baseline === null) {
      // First adoption: snapshot current paths and grandfather them all
      await this.saveBaseline(baselineFile, currentPaths, graph.tenantId);
      for (const p of currentPaths) {
        grandfatheredPaths.push(p);
      }

      return {
        passed: true,
        policy,
        violations: [],
        grandfatheredPaths,
        diffEvaluated: false,
        newPathsEvaluationStatus: 'NOT_EVALUABLE',
        summary: {
          totalViolations: 0,
          criticalViolations: 0,
          grandfatheredCount: grandfatheredPaths.length,
          totalEvaluated: 0,
        },
      };
    }

    if (baseline && policy.grandfatherExisting) {
      const baselineMap = new Map(baseline.paths.map((b) => [b.fingerprint, b.riskScore]));

      for (const p of currentPaths) {
        const fp = p.fingerprint || p.id;
        const baselineRisk = baselineMap.get(fp);

        if (baselineRisk !== undefined) {
          if (p.riskScore.totalRisk > baselineRisk + 0.1) {
            // Regressed path: worsened risk
            pathsToEvaluate.push(p);
          } else {
            // Unchanged or improved -> Grandfathered
            grandfatheredPaths.push(p);
          }
        } else {
          // New path introduced
          pathsToEvaluate.push(p);
        }
      }

      // Check max new paths against baseline diff
      const newPathsCount = currentPaths.filter(
        (p) => !baselineMap.has(p.fingerprint || p.id)
      ).length;

      if (newPathsCount > policy.maxNewPathsPerPR) {
        violations.push({
          rule: 'maxNewPathsPerPR',
          message: `Run introduced ${newPathsCount} new attack paths over baseline (policy budget limit: ${policy.maxNewPathsPerPR})`,
          severity: 'HIGH',
          actualValue: newPathsCount,
          limitValue: policy.maxNewPathsPerPR,
          pathId: pathsToEvaluate.map((p) => p.id).join(', '),
        });
      }
    } else {
      // All paths evaluated strictly
      pathsToEvaluate.push(...currentPaths);
    }

    // Filter by service selector if provided
    let filteredPaths = pathsToEvaluate;
    if (policy.serviceSelector) {
      const { tag, namespace } = policy.serviceSelector;
      filteredPaths = pathsToEvaluate.filter((p) => {
        const entryNode = graph.getNode(p.entryAssetId);
        const targetNode = graph.getNode(p.targetAssetId);
        const allTags = [
          ...(entryNode?.asset.tags ?? []),
          ...(targetNode?.asset.tags ?? []),
        ];
        const matchTag = tag ? allTags.includes(tag) : true;
        const matchNs = namespace
          ? entryNode?.asset.environment === namespace || targetNode?.asset.environment === namespace
          : true;
        return matchTag && matchNs;
      });
    }

    this.evaluatePathList(filteredPaths, policy, violations);

    const criticalViolations = violations.filter((v) => v.severity === 'CRITICAL').length;

    return {
      passed: violations.length === 0,
      policy,
      violations,
      grandfatheredPaths,
      diffEvaluated: baseline !== null,
      newPathsEvaluationStatus: baseline !== null ? 'EVALUATED' : 'NOT_EVALUABLE',
      summary: {
        totalViolations: violations.length,
        criticalViolations,
        grandfatheredCount: grandfatheredPaths.length,
        totalEvaluated: filteredPaths.length,
      },
    };
  }

  private evaluatePathList(
    paths: AttackPath[],
    policy: SecurityBudgetPolicy,
    violations: BudgetViolation[]
  ): void {
    let criticalPathCount = 0;
    let cumulativeRisk = 0;

    for (const path of paths) {
      const fp = path.fingerprint ?? '';
      if (fp && policy.allowlistFingerprints.includes(fp)) {
        continue;
      }

      cumulativeRisk += path.riskScore.totalRisk;

      if (path.riskScore.totalRisk >= 9.0) {
        criticalPathCount++;
      }

      // Max risk score per path
      if (path.riskScore.totalRisk > policy.maxRiskScorePerPath) {
        violations.push({
          rule: 'maxRiskScorePerPath',
          message: `Path ${path.id} has risk score ${path.riskScore.totalRisk} exceeding max allowed ${policy.maxRiskScorePerPath}`,
          severity: 'CRITICAL',
          pathId: path.id,
          pathFingerprint: fp,
          actualValue: path.riskScore.totalRisk,
          limitValue: policy.maxRiskScorePerPath,
        });
      }

      // Prohibited relationships
      if (policy.prohibitedRelationshipTypes.length > 0) {
        for (const step of path.steps) {
          if (policy.prohibitedRelationshipTypes.includes(step.relationshipType)) {
            violations.push({
              rule: 'prohibitedRelationshipType',
              message: `Path ${path.id} step ${step.stepNumber} uses prohibited relationship type '${step.relationshipType}'`,
              severity: 'HIGH',
              pathId: path.id,
              pathFingerprint: fp,
              actualValue: step.relationshipType,
              limitValue: policy.prohibitedRelationshipTypes.join(', '),
            });
          }
        }
      }
    }

    // Max total paths check
    if (policy.maxTotalPaths !== undefined && paths.length > policy.maxTotalPaths) {
      violations.push({
        rule: 'maxTotalPaths',
        message: `Total attack paths (${paths.length}) exceeds maximum allowed cap of ${policy.maxTotalPaths}`,
        severity: 'HIGH',
        actualValue: paths.length,
        limitValue: policy.maxTotalPaths,
      });
    }

    // Max critical paths count check
    if (criticalPathCount > policy.maxCriticalPaths) {
      violations.push({
        rule: 'maxCriticalPaths',
        message: `Discovered ${criticalPathCount} critical attack paths (policy budget limit: ${policy.maxCriticalPaths})`,
        severity: 'CRITICAL',
        actualValue: criticalPathCount,
        limitValue: policy.maxCriticalPaths,
      });
    }

    // Max total risk score check
    if (policy.maxTotalRiskScore !== undefined && cumulativeRisk > policy.maxTotalRiskScore) {
      violations.push({
        rule: 'maxTotalRiskScore',
        message: `Cumulative risk score ${cumulativeRisk.toFixed(1)} exceeds maximum risk budget of ${policy.maxTotalRiskScore}`,
        severity: 'HIGH',
        actualValue: Math.round(cumulativeRisk * 10) / 10,
        limitValue: policy.maxTotalRiskScore,
      });
    }
  }

  public async saveBaseline(
    filePath: string,
    paths: AttackPath[],
    tenantId: string
  ): Promise<void> {
    const dir = path.dirname(filePath);
    await fs.mkdir(dir, { recursive: true });

    const snapshot: BaselineSnapshot = {
      tenantId,
      snapshottedAt: new Date().toISOString(),
      paths: paths.map((p) => ({
        id: p.id,
        fingerprint: p.fingerprint || p.id,
        riskScore: p.riskScore.totalRisk,
        targetAssetId: p.targetAssetId,
      })),
    };

    await fs.writeFile(filePath, JSON.stringify(snapshot, null, 2), 'utf-8');
  }
}
