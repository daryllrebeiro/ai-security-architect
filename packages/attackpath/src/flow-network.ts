import type { RelationshipType } from '@ai-security-architect/core';

export interface FlowEdge {
  id: string;
  source: string;
  target: string;
  capacity: number;
  flow: number;
  reverseIndex: number;
  originalEdge?: {
    edgeId: string;
    relationshipType: RelationshipType;
    sourceAssetId: string;
    targetAssetId: string;
    actionDescription: string;
    blastRadius: 'LOW' | 'MEDIUM' | 'HIGH';
    engineeringEffort: 'LOW' | 'MEDIUM' | 'HIGH';
  };
}

export interface RemediationCostStrategy {
  getEdgeCost(params: {
    edgeId: string;
    sourceAssetId: string;
    targetAssetId: string;
    relationshipType: RelationshipType;
    blastRadius: 'LOW' | 'MEDIUM' | 'HIGH';
    engineeringEffort: 'LOW' | 'MEDIUM' | 'HIGH';
  }): number;
}

export class DefaultRemediationCostStrategy implements RemediationCostStrategy {
  public getEdgeCost(params: {
    edgeId: string;
    sourceAssetId: string;
    targetAssetId: string;
    relationshipType: RelationshipType;
    blastRadius: 'LOW' | 'MEDIUM' | 'HIGH';
    engineeringEffort: 'LOW' | 'MEDIUM' | 'HIGH';
  }): number {
    const blastMultiplier: Record<'LOW' | 'MEDIUM' | 'HIGH', number> = {
      LOW: 1.0,
      MEDIUM: 5.0,
      HIGH: 25.0,
    };
    const effortMultiplier: Record<'LOW' | 'MEDIUM' | 'HIGH', number> = {
      LOW: 1.0,
      MEDIUM: 2.0,
      HIGH: 4.0,
    };

    return blastMultiplier[params.blastRadius] * effortMultiplier[params.engineeringEffort];
  }
}

export class FlowNetwork {
  private readonly adj = new Map<string, FlowEdge[]>();
  private readonly edges: FlowEdge[] = [];

  public addVertex(v: string): void {
    if (!this.adj.has(v)) {
      this.adj.set(v, []);
    }
  }

  public addEdge(
    source: string,
    target: string,
    capacity: number,
    originalEdge?: FlowEdge['originalEdge'],
    id?: string
  ): void {
    this.addVertex(source);
    this.addVertex(target);

    const forwardEdge: FlowEdge = {
      id: id ?? `${source}->${target}`,
      source,
      target,
      capacity,
      flow: 0,
      reverseIndex: -1,
      originalEdge,
    };

    const reverseEdge: FlowEdge = {
      id: `rev-${forwardEdge.id}`,
      source: target,
      target: source,
      capacity: 0,
      flow: 0,
      reverseIndex: -1,
    };

    const sourceAdj = this.adj.get(source)!;
    const targetAdj = this.adj.get(target)!;

    forwardEdge.reverseIndex = targetAdj.length;
    reverseEdge.reverseIndex = sourceAdj.length;

    sourceAdj.push(forwardEdge);
    targetAdj.push(reverseEdge);
    this.edges.push(forwardEdge);
  }

  /**
   * Dinic's Algorithm: Computes maximum flow from source to sink.
   */
  public computeMaxFlow(source: string, sink: string): number {
    let maxFlow = 0;

    const level = new Map<string, number>();
    const ptr = new Map<string, number>();

    const bfs = (): boolean => {
      level.clear();
      const queue: string[] = [source];
      level.set(source, 0);

      while (queue.length > 0) {
        const u = queue.shift()!;
        const edges = this.adj.get(u) || [];

        for (const e of edges) {
          if (e.capacity - e.flow > 1e-9 && !level.has(e.target)) {
            level.set(e.target, level.get(u)! + 1);
            queue.push(e.target);
          }
        }
      }

      return level.has(sink);
    };

    const dfs = (u: string, pushed: number): number => {
      if (pushed <= 0) return 0;
      if (u === sink) return pushed;

      const edges = this.adj.get(u) || [];
      const currentPtr = ptr.get(u) || 0;

      for (let cid = currentPtr; cid < edges.length; cid++) {
        ptr.set(u, cid);
        const e = edges[cid];
        const trg = e.target;

        if (level.get(u)! + 1 !== level.get(trg)) continue;

        const tr = e.capacity - e.flow;
        if (tr <= 1e-9) continue;

        const push = dfs(trg, Math.min(pushed, tr));
        if (push <= 0) continue;

        e.flow += push;
        const revEdge = this.adj.get(trg)![e.reverseIndex];
        revEdge.flow -= push;
        return push;
      }

      return 0;
    };

    while (bfs()) {
      ptr.clear();
      while (true) {
        const pushed = dfs(source, Number.POSITIVE_INFINITY);
        if (pushed <= 0) break;
        maxFlow += pushed;
      }
    }

    return maxFlow;
  }

  /**
   * Identifies the Minimum Cut-Set edges after max flow computation.
   */
  public findMinCut(source: string): FlowEdge[] {
    const visited = new Set<string>();
    const queue: string[] = [source];
    visited.add(source);

    while (queue.length > 0) {
      const u = queue.shift()!;
      const edges = this.adj.get(u) || [];

      for (const e of edges) {
        if (e.capacity - e.flow > 1e-9 && !visited.has(e.target)) {
          visited.add(e.target);
          queue.push(e.target);
        }
      }
    }

    const minCutEdges: FlowEdge[] = [];
    for (const e of this.edges) {
      if (e.capacity > 0 && visited.has(e.source) && !visited.has(e.target)) {
        minCutEdges.push(e);
      }
    }

    return minCutEdges;
  }
}
