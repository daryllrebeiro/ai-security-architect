import { describe, it, expect } from 'vitest';
import { Asset, Relationship } from '@ai-security-architect/core';
import {
  VendorRiskExtender,
  VENDOR_PROVENANCE_LABEL,
} from '../src/vendor-risk/index.js';

describe('Task H.2: Third-Party / Vendor Risk Graph Layer', () => {
  const extender = new VendorRiskExtender({
    enabled: true,
    knownVendors: [
      {
        vendorId: 'vendor-analytics-inc',
        vendorName: 'AnalyticsInc SaaS',
        matchedDomains: ['api.analytics-vendor.test', 'analytics.vendor.io'],
        certifications: [], // Uncertified!
        hasPublicBreachHistory: true, // Known breach!
        questionnaireScore: 42,
        riskTier: 'CRITICAL',
      },
      {
        vendorId: 'vendor-stripe',
        vendorName: 'Stripe Payments',
        matchedDomains: ['api.stripe.test'],
        certifications: ['SOC2_TYPE_II', 'PCI_DSS_LEVEL_1'],
        hasPublicBreachHistory: false,
        questionnaireScore: 98,
        riskTier: 'LOW',
      },
    ],
  });

  it('attaches VENDOR nodes with clearly-labeled externally-sourced risk metadata when outbound data flows to vendor', () => {
    const assets: Asset[] = [
      {
        id: 'asset-svc-checkout',
        tenantId: 'tenant-1',
        type: 'SERVICE',
        name: 'checkout-service',
        environment: 'production',
        isPublic: false,
        isSensitiveData: false,
        criticality: 'HIGH',
        metadata: {},
        tags: ['backend'],
      },
    ];

    const relationships: Relationship[] = [
      {
        id: 'rel-flow-vendor',
        tenantId: 'tenant-1',
        sourceAssetId: 'asset-svc-checkout',
        targetAssetId: 'external-analytics-endpoint',
        type: 'DATA_FLOW',
        nature: 'DECLARED',
        confidence: 0.9,
        metadata: {
          destinationUrl: 'https://api.analytics-vendor.test/v2/events',
          containsSensitiveData: true,
          piiTypes: ['EMAIL', 'IP_ADDRESS'],
        },
      },
    ];

    const result = extender.enrichGraphWithVendors(assets, relationships);

    // 1. Assert vendor asset was created
    expect(result.newVendorAssets.length).toBe(1);
    const vendorAsset = result.newVendorAssets[0];
    expect(vendorAsset.type).toBe('VENDOR');
    expect(vendorAsset.name).toBe('AnalyticsInc SaaS');
    expect(vendorAsset.metadata.provenanceLabel).toBe(VENDOR_PROVENANCE_LABEL);
    expect(vendorAsset.metadata.hasPublicBreachHistory).toBe(true);

    // 2. Assert vendor risk finding was raised with FAIR loss multiplier
    expect(result.vendorFindings.length).toBe(1);
    const finding = result.vendorFindings[0];
    expect(finding.category).toBe('THIRD_PARTY_VENDOR_RISK');
    expect(finding.severity).toBe('CRITICAL');
    expect(finding.confidence).toBe('MEDIUM'); // External data labeled lower confidence
    expect(finding.description).toContain(VENDOR_PROVENANCE_LABEL);

    // 3. Assert FAIR multiplier
    expect(result.summaries[0].fairLossMultiplier).toBe(1.8);
  });

  it('does NOT create vendor nodes or findings for purely internal data flows', () => {
    const assets: Asset[] = [
      {
        id: 'asset-svc-order',
        tenantId: 'tenant-1',
        type: 'SERVICE',
        name: 'order-service',
        environment: 'production',
        isPublic: false,
        isSensitiveData: false,
        criticality: 'MEDIUM',
        metadata: {},
        tags: [],
      },
      {
        id: 'asset-db-orders',
        tenantId: 'tenant-1',
        type: 'DATABASE',
        name: 'orders-postgres',
        environment: 'production',
        isPublic: false,
        isSensitiveData: true,
        criticality: 'HIGH',
        metadata: {},
        tags: [],
      },
    ];

    const relationships: Relationship[] = [
      {
        id: 'rel-internal-flow',
        tenantId: 'tenant-1',
        sourceAssetId: 'asset-svc-order',
        targetAssetId: 'asset-db-orders',
        type: 'DATA_FLOW',
        nature: 'DECLARED',
        confidence: 1.0,
        metadata: {
          destinationUrl: 'postgresql://postgres.internal:5432/orders',
          containsSensitiveData: true,
        },
      },
    ];

    const result = extender.enrichGraphWithVendors(assets, relationships);

    expect(result.newVendorAssets.length).toBe(0);
    expect(result.vendorFindings.length).toBe(0);
    expect(result.summaries.length).toBe(0);
  });
});
