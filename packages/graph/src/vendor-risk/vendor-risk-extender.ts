import {
  Asset,
  Relationship,
  Finding,
  createEvidence,
} from '@ai-security-architect/core';
import {
  VendorAttestation,
  VendorRiskSummary,
  VENDOR_PROVENANCE_LABEL,
} from './types.js';

export interface VendorRiskConfig {
  enabled: boolean;
  knownVendors?: VendorAttestation[];
}

export class VendorRiskExtender {
  private vendorCatalog: Map<string, VendorAttestation> = new Map();
  private domainLookup: Map<string, VendorAttestation> = new Map();

  constructor(config: VendorRiskConfig) {
    if (config.knownVendors) {
      for (const v of config.knownVendors) {
        this.vendorCatalog.set(v.vendorId, v);
        for (const dom of v.matchedDomains) {
          this.domainLookup.set(dom.toLowerCase(), v);
        }
      }
    }
  }

  registerVendor(attestation: VendorAttestation): void {
    this.vendorCatalog.set(attestation.vendorId, attestation);
    for (const dom of attestation.matchedDomains) {
      this.domainLookup.set(dom.toLowerCase(), attestation);
    }
  }

  /**
   * Matches outbound DATA_FLOW edges against external vendor signatures.
   * Creates VENDOR nodes, attaches clearly-labeled risk attributes, and computes FAIR loss multipliers.
   */
  enrichGraphWithVendors(
    assets: Asset[],
    relationships: Relationship[]
  ): {
    newVendorAssets: Asset[];
    updatedRelationships: Relationship[];
    vendorFindings: Finding[];
    summaries: VendorRiskSummary[];
  } {
    const newVendorAssets: Asset[] = [];
    const updatedRelationships: Relationship[] = [...relationships];
    const vendorFindings: Finding[] = [];
    const summaries: VendorRiskSummary[] = [];

    const existingAssetIds = new Set(assets.map((a) => a.id));
    const createdVendorIds = new Set<string>();

    for (const rel of relationships) {
      if (rel.type !== 'DATA_FLOW') continue;

      // Check if destination is marked as external vendor or matches domain
      const destUrl = typeof rel.metadata?.destinationUrl === 'string' ? rel.metadata.destinationUrl : '';
      const vendorNameMeta = typeof rel.metadata?.externalVendorName === 'string' ? rel.metadata.externalVendorName : '';
      const isExplicitExternal = Boolean(rel.metadata?.isExternalVendor);

      let matchedAttestation: VendorAttestation | undefined;

      // 1. Match by domain if URL present
      if (destUrl) {
        for (const [domain, att] of this.domainLookup.entries()) {
          if (destUrl.toLowerCase().includes(domain)) {
            matchedAttestation = att;
            break;
          }
        }
      }

      // 2. Match by explicit vendor name
      if (!matchedAttestation && vendorNameMeta) {
        matchedAttestation = this.vendorCatalog.get(vendorNameMeta) || Array.from(this.vendorCatalog.values()).find(
          (v) => v.vendorName.toLowerCase() === vendorNameMeta.toLowerCase()
        );
      }

      // If no external vendor pattern matched, this flow is purely internal -> Do NOT create vendor node!
      if (!matchedAttestation && !isExplicitExternal) {
        continue;
      }

      const vendorId = matchedAttestation ? `asset-vendor-${matchedAttestation.vendorId}` : `asset-vendor-${rel.targetAssetId}`;
      const vendorName = matchedAttestation ? matchedAttestation.vendorName : vendorNameMeta || 'External Vendor Service';
      const riskTier = matchedAttestation?.riskTier || 'MEDIUM';
      const hasBreach = Boolean(matchedAttestation?.hasPublicBreachHistory);
      const certs = matchedAttestation?.certifications || [];
      const hasSoc2 = certs.includes('SOC2_TYPE_II');

      // Create VENDOR node if not already created
      if (!existingAssetIds.has(vendorId) && !createdVendorIds.has(vendorId)) {
        createdVendorIds.add(vendorId);
        newVendorAssets.push({
          id: vendorId,
          tenantId: rel.tenantId,
          type: 'VENDOR',
          name: vendorName,
          environment: 'external-saas',
          isPublic: true,
          isSensitiveData: false,
          criticality: riskTier === 'CRITICAL' ? 'CRITICAL' : riskTier === 'HIGH' ? 'HIGH' : 'MEDIUM',
          tags: ['third-party', 'vendor', `risk-${riskTier.toLowerCase()}`],
          metadata: {
            provenanceLabel: VENDOR_PROVENANCE_LABEL,
            certifications: certs,
            hasPublicBreachHistory: hasBreach,
            questionnaireScore: matchedAttestation?.questionnaireScore,
            riskTier,
          },
        });
      }

      // Calculate FAIR loss magnitude multiplier
      let fairLossMultiplier = 1.0;
      if (riskTier === 'CRITICAL' || hasBreach) {
        fairLossMultiplier = 1.8;
      } else if (riskTier === 'HIGH' || !hasSoc2) {
        fairLossMultiplier = 1.4;
      } else {
        fairLossMultiplier = 1.05;
      }

      const isSensitiveDataFlow = Boolean(rel.metadata?.containsSensitiveData || rel.metadata?.piiTypes);

      summaries.push({
        vendorId,
        vendorName,
        transfersSensitiveData: isSensitiveDataFlow,
        riskTier,
        fairLossMultiplier,
        certifications: certs,
        hasBreachHistory: hasBreach,
        provenanceLabel: VENDOR_PROVENANCE_LABEL,
      });

      // Raise finding if sensitive data flows to high-risk or uncertified vendor
      if (isSensitiveDataFlow && (riskTier === 'HIGH' || riskTier === 'CRITICAL' || hasBreach || !hasSoc2)) {
        vendorFindings.push({
          id: `finding-vendor-risk-${rel.id}`,
          tenantId: rel.tenantId,
          assetId: vendorId,
          category: 'THIRD_PARTY_VENDOR_RISK',
          ruleId: 'VENDOR-RISK-001',
          title: `Third-Party Risk: Sensitive Data Flow to ${vendorName} [${riskTier} Risk]`,
          description: `Sensitive customer data flows to external SaaS vendor ${vendorName}. ${VENDOR_PROVENANCE_LABEL}. Security posture signals: Certifications: [${certs.join(', ') || 'None Reported'}], Public Breach History: ${hasBreach ? 'YES' : 'No'}. Estimated FAIR loss magnitude multiplier: ${fairLossMultiplier}x.`,
          severity: riskTier === 'CRITICAL' || hasBreach ? 'CRITICAL' : 'HIGH',
          confidence: 'MEDIUM', // External data is lower confidence than graph topology
          scanner: 'vendor-risk-extender',
          evidence: createEvidence({
            id: `ev-vendor-${rel.id}`,
            tenantId: rel.tenantId,
            sourceType: 'RUNTIME_TRACE',
            repository: 'architecture/vendors',
            filePath: destUrl || `vendor://${vendorId}`,
            lineStart: 1,
            lineEnd: 1,
            snippet: `Outbound flow: source=${rel.sourceAssetId} -> vendor=${vendorName} (URL: ${destUrl})`,
            scanner: 'vendor-risk-extender',
          }),
          remediationRecommendation: `Review vendor data processing agreement (DPA), confirm SOC 2 Type II audit report, or implement client-side encryption/tokenization before transmitting sensitive records.`,
          metadata: {
            vendorName,
            riskTier,
            fairLossMultiplier,
            provenanceLabel: VENDOR_PROVENANCE_LABEL,
          },
        });
      }
    }

    return {
      newVendorAssets,
      updatedRelationships,
      vendorFindings,
      summaries,
    };
  }
}
