export interface CrownJewelInvariant {
  name: string;
  crownJewelAssetId: string;
  entryNodeId: string;
  description?: string;
  maxHops?: number;
}

export interface ConditionalEdge {
  id: string;
  fromAssetId: string;
  toAssetId: string;
  conditionVar?: string; // Boolean variable controlling edge activation, e.g. "enable_bastion"
  negated?: boolean;     // If true, edge is active when conditionVar is false
}

export interface SubgraphSpecification {
  nodeIds: string[];
  edges: ConditionalEdge[];
  configurationVariables: string[]; // List of boolean variables
}

export interface FormalVerificationResult {
  invariantName: string;
  crownJewelAssetId: string;
  entryNodeId: string;
  provenSafe: boolean; // true = UNSAT (proven unreachable across all configurations), false = SAT (counterexample found)
  configurationVariables: string[];
  totalConfigurationSpace: number; // 2^N
  counterexample?: Record<string, boolean>; // Concrete configuration causing exposure
  violatingPath?: string[]; // Node ID sequence under the counterexample
  scopeDisclaimer: string;
}
