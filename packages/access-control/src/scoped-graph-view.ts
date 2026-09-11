import type { SecurityGraphEngine, GraphNode } from '@ai-security-architect/graph';
import type { AttackPath, Finding } from '@ai-security-architect/core';
import type { ScopedPathRedactionResult, UserScope } from './types.js';
import { PartialDisclosurePolicy } from './partial-disclosure.js';

export class ScopedGraphView {
  constructor(
    public readonly graph: SecurityGraphEngine,
    public readonly scope: UserScope
  ) {}

  public getNode(assetId: string): GraphNode | undefined {
    const node = this.graph.getNode(assetId);
    if (!node) return undefined;
    if (!PartialDisclosurePolicy.canAccessAsset(this.scope, node.asset)) {
      return undefined;
    }
    return node;
  }

  public getAllNodes(): GraphNode[] {
    return this.graph
      .getAllNodes()
      .filter((n) => PartialDisclosurePolicy.canAccessAsset(this.scope, n.asset));
  }

  public getAllFindings(): Finding[] {
    const accessibleNodes = new Set(this.getAllNodes().map((n) => n.asset.id));
    return this.graph.getAllFindings().filter((f) => accessibleNodes.has(f.assetId));
  }

  public getAttackPaths(allPaths: AttackPath[]): AttackPath[] {
    const results: AttackPath[] = [];

    for (const path of allPaths) {
      const { path: redactedPath } = PartialDisclosurePolicy.redactCrossBoundaryAttackPath(
        this.scope,
        path,
        (id) => this.graph.getNode(id)?.asset
      );

      if (redactedPath !== null) {
        results.push(redactedPath);
      }
    }

    return results;
  }

  public filterCrossBoundaryPaths(allPaths: AttackPath[]): ScopedPathRedactionResult[] {
    const results: ScopedPathRedactionResult[] = [];

    for (const path of allPaths) {
      const outcome = PartialDisclosurePolicy.redactCrossBoundaryAttackPath(
        this.scope,
        path,
        (id) => this.graph.getNode(id)?.asset
      );

      if (outcome.path !== null) {
        results.push(outcome);
      }
    }

    return results;
  }
}
