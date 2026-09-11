import {
  CrownJewelInvariant,
  SubgraphSpecification,
  FormalVerificationResult,
} from './types.js';

export const FORMAL_PROOF_DISCLAIMER =
  'Formal proof holds strictly over the declared boolean configuration space represented in the analyzed subgraph and IaC. It is NOT a proof against software implementation bugs, runtime 0-day exploits, or infrastructure misconfigurations outside the modeled graph.';

export class FormalVerificationEngine {
  /**
   * Formally verify whether a crown-jewel invariant holds across the entire space of configuration variables.
   * Uses propositional reachability analysis over 2^N variable assignments.
   * - UNSAT: No assignment produces a path -> provenSafe: true.
   * - SAT: An assignment produces a path -> provenSafe: false with concrete counterexample assignment.
   */
  verifyInvariant(
    subgraph: SubgraphSpecification,
    invariant: CrownJewelInvariant
  ): FormalVerificationResult {
    const vars = subgraph.configurationVariables;
    const n = vars.length;
    const totalAssignments = Math.pow(2, n);

    // Evaluate all 2^N possible configuration assignments
    for (let i = 0; i < totalAssignments; i++) {
      const assignment: Record<string, boolean> = {};
      for (let bit = 0; bit < n; bit++) {
        assignment[vars[bit]] = Boolean((i >> bit) & 1);
      }

      // Check if path exists under this specific configuration assignment
      const path = this.findReachablePath(subgraph, invariant.entryNodeId, invariant.crownJewelAssetId, assignment, invariant.maxHops ?? 10);
      if (path !== null) {
        // Satisfiable: A configuration produces exposure -> Counterexample found!
        return {
          invariantName: invariant.name,
          crownJewelAssetId: invariant.crownJewelAssetId,
          entryNodeId: invariant.entryNodeId,
          provenSafe: false,
          configurationVariables: vars,
          totalConfigurationSpace: totalAssignments,
          counterexample: assignment,
          violatingPath: path,
          scopeDisclaimer: FORMAL_PROOF_DISCLAIMER,
        };
      }
    }

    // Unsatisfiable across the entire configuration space: Invariant is formally proven safe!
    return {
      invariantName: invariant.name,
      crownJewelAssetId: invariant.crownJewelAssetId,
      entryNodeId: invariant.entryNodeId,
      provenSafe: true,
      configurationVariables: vars,
      totalConfigurationSpace: totalAssignments,
      scopeDisclaimer: FORMAL_PROOF_DISCLAIMER,
    };
  }

  private findReachablePath(
    subgraph: SubgraphSpecification,
    startNode: string,
    targetNode: string,
    assignment: Record<string, boolean>,
    maxHops: number
  ): string[] | null {
    if (startNode === targetNode) return [startNode];

    // Build adjacency list of active edges under this configuration assignment
    const adj: Map<string, string[]> = new Map();
    for (const node of subgraph.nodeIds) {
      adj.set(node, []);
    }

    for (const edge of subgraph.edges) {
      let isActive = true;
      if (edge.conditionVar) {
        const varValue = Boolean(assignment[edge.conditionVar]);
        isActive = edge.negated ? !varValue : varValue;
      }

      if (isActive) {
        const neighbors = adj.get(edge.fromAssetId) || [];
        neighbors.push(edge.toAssetId);
        adj.set(edge.fromAssetId, neighbors);
      }
    }

    // BFS to find reachability and path
    const queue: Array<{ node: string; path: string[] }> = [{ node: startNode, path: [startNode] }];
    const visited = new Set<string>([startNode]);

    while (queue.length > 0) {
      const current = queue.shift()!;
      if (current.path.length > maxHops + 1) continue;

      if (current.node === targetNode) {
        return current.path;
      }

      const neighbors = adj.get(current.node) || [];
      for (const neighbor of neighbors) {
        if (!visited.has(neighbor)) {
          visited.add(neighbor);
          queue.push({
            node: neighbor,
            path: [...current.path, neighbor],
          });
        }
      }
    }

    return null;
  }
}
