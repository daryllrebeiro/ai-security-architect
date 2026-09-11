import type { AttackPath } from '@ai-security-architect/core';
import type { SecurityGraphEngine } from '@ai-security-architect/graph';
import type { LLMProvider } from './types.js';

export type AgentPersonaType = 'IAM_SPECIALIST' | 'NETWORK_ARCHITECT' | 'APP_DEVELOPER';

export interface PersonaProposal {
  persona: AgentPersonaType;
  title: string;
  recommendedAction: string;
  securityEfficacyScore: number; // 0 - 10
  operationalBlastRadius: number; // 0 (none) - 10 (high risk of outage)
  implementationFriction: number; // 0 (trivial) - 10 (high complexity)
  justification: string;
  risksAndMitigations: string[];
}

export interface ArbitrationDecision {
  attackPathId: string;
  winningPersona: AgentPersonaType;
  selectedStrategy: string;
  consensusScore: number; // Net weighted score
  personaProposals: PersonaProposal[];
  consensusRationale: string;
  operationalSafeguards: string[];
  arbitratedAt: string;
}

export interface ArbitratorOptions {
  llmProvider?: LLMProvider;
  weights?: {
    securityEfficacy?: number;
    blastRadiusPenalty?: number;
    frictionPenalty?: number;
  };
}

export class MultiAgentArbitrator {
  private readonly llmProvider?: LLMProvider;
  private readonly weights: {
    securityEfficacy: number;
    blastRadiusPenalty: number;
    frictionPenalty: number;
  };

  constructor(options: ArbitratorOptions = {}) {
    this.llmProvider = options.llmProvider;
    this.weights = {
      securityEfficacy: options.weights?.securityEfficacy ?? 1.5,
      blastRadiusPenalty: options.weights?.blastRadiusPenalty ?? 1.0,
      frictionPenalty: options.weights?.frictionPenalty ?? 0.8,
    };
  }

  public generatePersonaProposals(
    attackPath: AttackPath,
    graph: SecurityGraphEngine
  ): PersonaProposal[] {
    const entry = graph.getNode(attackPath.entryAssetId);
    const target = graph.getNode(attackPath.targetAssetId);
    const entryName = entry?.asset.name ?? attackPath.entryAssetId;
    const targetName = target?.asset.name ?? attackPath.targetAssetId;

    const proposals: PersonaProposal[] = [];

    // 1. IAM Specialist
    proposals.push({
      persona: 'IAM_SPECIALIST',
      title: `Least-Privilege Scoping on Assumed Credentials`,
      recommendedAction: `Restrict IAM permissions on workload identity to read-only scoped strictly to required ARN prefix on ${targetName}. Remove wildcard actions (s3:*, iam:*).`,
      securityEfficacyScore: 9.2,
      operationalBlastRadius: 3.5, // Low-moderate risk of missing a required sub-action
      implementationFriction: 2.5,
      justification: `Directly severs authorization to ${targetName} even if upstream container or network boundary is compromised.`,
      risksAndMitigations: [
        `Risk: Application might require unmapped sub-action during peak load.`,
        `Mitigation: Review CloudTrail access history for 30 days prior to applying restriction.`,
      ],
    });

    // 2. Network Architect
    proposals.push({
      persona: 'NETWORK_ARCHITECT',
      title: `Network Ingress Isolation & Private Link Endpoint`,
      recommendedAction: `Remove public routing from ${entryName} and place behind internal ALB / VPC Endpoint with Security Group restricting port 443 strictly to corporate CIDR.`,
      securityEfficacyScore: 8.8,
      operationalBlastRadius: 6.0, // High risk if external clients depend on direct ingress
      implementationFriction: 5.0,
      justification: `Completely denies attacker ability to initiate TCP handshake from public internet.`,
      risksAndMitigations: [
        `Risk: Public consumers or third-party webhooks may experience immediate connection timeouts.`,
        `Mitigation: Introduce ingress API Gateway with mTLS or WAF IP rate limiting rather than hard private isolation if public access is intentional.`,
      ],
    });

    // 3. Application Developer
    proposals.push({
      persona: 'APP_DEVELOPER',
      title: `Application Input Validation & Guardrail Middleware`,
      recommendedAction: `Add input validation and SSRF sanitization middleware in application codebase to filter malicious redirects and internal IP lookups.`,
      securityEfficacyScore: 7.0,
      operationalBlastRadius: 1.5, // Lowest infrastructure blast radius, purely in app code
      implementationFriction: 3.0,
      justification: `Preserves existing network topology and cloud permissions; fixes defect in application layer where vulnerability originates.`,
      risksAndMitigations: [
        `Risk: Bypasses may exist if attacker uses DNS rebinding or hex-encoded loopbacks.`,
        `Mitigation: Combine with DNS egress resolution firewalls.`,
      ],
    });

    return proposals;
  }

  public calculateNetScore(proposal: PersonaProposal): number {
    const raw =
      proposal.securityEfficacyScore * this.weights.securityEfficacy -
      proposal.operationalBlastRadius * this.weights.blastRadiusPenalty -
      proposal.implementationFriction * this.weights.frictionPenalty;
    return Math.max(0, Math.round(raw * 10) / 10);
  }

  public arbitrate(
    attackPath: AttackPath,
    graph: SecurityGraphEngine
  ): ArbitrationDecision {
    const proposals = this.generatePersonaProposals(attackPath, graph);

    let highestScore = -Infinity;
    let winningProposal = proposals[0];

    for (const proposal of proposals) {
      const score = this.calculateNetScore(proposal);
      if (score > highestScore) {
        highestScore = score;
        winningProposal = proposal;
      }
    }

    const consensusRationale =
      `Arbitration reached consensus favoring ${winningProposal.persona} (${winningProposal.title}). ` +
      `With a security efficacy of ${winningProposal.securityEfficacyScore}/10 and a manageable blast radius of ` +
      `${winningProposal.operationalBlastRadius}/10, this strategy yielded the highest net consensus score of ` +
      `${highestScore.toFixed(1)} compared to other candidates.`;

    const operationalSafeguards = [
      ...winningProposal.risksAndMitigations,
      `Canary deployment: Apply changes to staging environment first with automated integration tests.`,
      `Zero-downtime rollback: Maintain previous configuration snapshot for instantaneous reversal upon anomaly detection.`,
    ];

    return {
      attackPathId: attackPath.id,
      winningPersona: winningProposal.persona,
      selectedStrategy: winningProposal.recommendedAction,
      consensusScore: highestScore,
      personaProposals: proposals,
      consensusRationale,
      operationalSafeguards,
      arbitratedAt: new Date().toISOString(),
    };
  }
}
