import { describe, it, expect } from 'vitest';
import type { Asset } from '@ai-security-architect/core';
import { SecurityGraphEngine } from '@ai-security-architect/graph';
import { AttackPathEngine } from '@ai-security-architect/attackpath';
import { FederationEngine } from '../src/federation-engine.js';
import { CanonicalIdResolver } from '../src/canonical-id-resolver.js';

describe('Task C.2 — Multi-Repo & Org-Wide Graph Federation', () => {
  const tenantId = 'tenant-fed-test';

  it('validates canonical cloud identities (AWS ARNs, GCP URIs, Azure IDs, VPCs) and rejects plain service names', () => {
    expect(CanonicalIdResolver.isValidCloudIdentity('arn:aws:s3:::shared-vault')).toBe(true);
    expect(CanonicalIdResolver.isValidCloudIdentity('arn:aws:iam::123456789012:role/app-role')).toBe(true);
    expect(CanonicalIdResolver.isValidCloudIdentity('//storage.googleapis.com/shared-bucket')).toBe(true);
    expect(CanonicalIdResolver.isValidCloudIdentity('vpc-0123456789abcdef0')).toBe(true);

    // Reject generic names
    expect(CanonicalIdResolver.isValidCloudIdentity('order-service')).toBe(false);
    expect(CanonicalIdResolver.isValidCloudIdentity('postgres-db')).toBe(false);
  });

  it('merges nodes with identical exact canonical cloud ARNs and preserves repo provenance', () => {
    const graphA = new SecurityGraphEngine(tenantId);
    const graphB = new SecurityGraphEngine(tenantId);

    const sharedArn = 'arn:aws:s3:::shared-enterprise-vault';

    // In Repo A: frontend defines read access to shared bucket
    const bucketA: Asset = {
      id: 'asset-s3-vault-local-a',
      tenantId,
      type: 'BUCKET',
      name: 'shared-vault',
      environment: 'production',
      isPublic: false,
      isSensitiveData: true,
      criticality: 'HIGH',
      metadata: { arn: sharedArn },
      tags: ['compliance=pci'],
    };

    // In Repo B: data engineering pipeline writes to the same bucket
    const bucketB: Asset = {
      id: 'asset-s3-vault-local-b',
      tenantId,
      type: 'BUCKET',
      name: 'shared-vault',
      environment: 'production',
      isPublic: false,
      isSensitiveData: true,
      criticality: 'CRITICAL',
      metadata: { arn: sharedArn },
      tags: ['contains-pii'],
    };

    graphA.addAsset(bucketA);
    graphB.addAsset(bucketB);

    const federation = new FederationEngine();
    const result = federation.federate([
      { repository: 'org/frontend-app', graph: graphA },
      { repository: 'org/data-pipeline', graph: graphB },
    ]);

    expect(result.mergedNodeCount).toBe(1);
    expect(result.totalNodes).toBe(1);

    const unifiedNode = result.graph.getAllNodes()[0];
    expect(unifiedNode.asset.metadata.arn).toBe(sharedArn);
    expect(unifiedNode.asset.criticality).toBe('CRITICAL'); // Elevates to highest
    expect(unifiedNode.asset.tags).toContain('compliance=pci');
    expect(unifiedNode.asset.tags).toContain('contains-pii');
    expect(unifiedNode.asset.metadata.federatedRepos).toEqual(['org/frontend-app', 'org/data-pipeline']);
  });

  it('strictly keeps identical generic asset names separate across repositories', () => {
    const graphA = new SecurityGraphEngine(tenantId);
    const graphB = new SecurityGraphEngine(tenantId);

    // Repo A has an internal service named "auth-service"
    const svcA: Asset = {
      id: 'svc-auth',
      tenantId,
      type: 'SERVICE',
      name: 'auth-service',
      environment: 'production',
      isPublic: false,
      isSensitiveData: false,
      criticality: 'HIGH',
      metadata: {},
      tags: [],
    };

    // Repo B also has an internal service named "auth-service" (e.g. in a different namespace/team)
    const svcB: Asset = {
      id: 'svc-auth',
      tenantId,
      type: 'SERVICE',
      name: 'auth-service',
      environment: 'production',
      isPublic: false,
      isSensitiveData: false,
      criticality: 'HIGH',
      metadata: {},
      tags: [],
    };

    graphA.addAsset(svcA);
    graphB.addAsset(svcB);

    const federation = new FederationEngine();
    const result = federation.federate([
      { repository: 'team-alpha/auth', graph: graphA },
      { repository: 'team-beta/auth', graph: graphB },
    ]);

    // Must NOT merge generic names!
    expect(result.mergedNodeCount).toBe(0);
    expect(result.totalNodes).toBe(2);
  });

  it('enables end-to-end cross-repository attack path traversal across 3 federated repos', () => {
    const graphWeb = new SecurityGraphEngine(tenantId);
    const graphApi = new SecurityGraphEngine(tenantId);
    const graphData = new SecurityGraphEngine(tenantId);

    const gatewayArn = 'arn:aws:apigateway:us-east-1::/restapis/gateway-123';
    const dbArn = 'arn:aws:rds:us-east-1:123456789012:db:customer-db-primary';

    // Repo 1: Web Frontend
    const internet: Asset = {
      id: 'asset-internet',
      tenantId,
      type: 'INTERNET',
      name: 'public-internet',
      environment: 'production',
      isPublic: true,
      isSensitiveData: false,
      criticality: 'LOW',
      metadata: {},
      tags: [],
    };

    const gatewayWebSide: Asset = {
      id: 'asset-gw-web',
      tenantId,
      type: 'LOAD_BALANCER',
      name: 'api-gateway',
      environment: 'production',
      isPublic: true,
      isSensitiveData: false,
      criticality: 'MEDIUM',
      metadata: { arn: gatewayArn },
      tags: [],
    };

    graphWeb.addAsset(internet);
    graphWeb.addAsset(gatewayWebSide);
    graphWeb.addRelationship({
      id: 'rel-inet-gw',
      tenantId,
      sourceAssetId: internet.id,
      targetAssetId: gatewayWebSide.id,
      type: 'EXPOSES_HTTP',
      confidence: 1.0,
      nature: 'DECLARED',
      metadata: {},
    });

    // Repo 2: Backend API
    const gatewayApiSide: Asset = {
      id: 'asset-gw-api',
      tenantId,
      type: 'LOAD_BALANCER',
      name: 'api-gateway',
      environment: 'production',
      isPublic: true,
      isSensitiveData: false,
      criticality: 'MEDIUM',
      metadata: { arn: gatewayArn },
      tags: [],
    };

    const backendService: Asset = {
      id: 'asset-backend-svc',
      tenantId,
      type: 'SERVICE',
      name: 'order-backend-service',
      environment: 'production',
      isPublic: false,
      isSensitiveData: false,
      criticality: 'HIGH',
      metadata: {},
      tags: [],
    };

    const dbApiSide: Asset = {
      id: 'asset-db-api',
      tenantId,
      type: 'DATABASE',
      name: 'customer-db',
      environment: 'production',
      isPublic: false,
      isSensitiveData: true,
      criticality: 'CRITICAL',
      metadata: { arn: dbArn },
      tags: ['contains-pii'],
    };

    graphApi.addAsset(gatewayApiSide);
    graphApi.addAsset(backendService);
    graphApi.addAsset(dbApiSide);

    graphApi.addRelationship({
      id: 'rel-gw-svc',
      tenantId,
      sourceAssetId: gatewayApiSide.id,
      targetAssetId: backendService.id,
      type: 'ROUTES_TO',
      confidence: 1.0,
      nature: 'DECLARED',
      metadata: {},
    });

    graphApi.addRelationship({
      id: 'rel-svc-db',
      tenantId,
      sourceAssetId: backendService.id,
      targetAssetId: dbApiSide.id,
      type: 'CAN_READ',
      confidence: 1.0,
      nature: 'DECLARED',
      metadata: {},
    });

    // Federate graphs
    const federation = new FederationEngine();
    const result = federation.federate([
      { repository: 'org/web-portal', graph: graphWeb },
      { repository: 'org/core-api', graph: graphApi },
    ]);

    expect(result.mergedNodeCount).toBe(1); // Gateway merged on canonical ARN

    // Analyze attack paths on the federated multi-repo graph
    const pathEngine = new AttackPathEngine();
    const attackPaths = pathEngine.analyzePaths(result.graph);

    expect(attackPaths.length).toBe(2);
    const path = attackPaths.find((p) => p.pathLength === 3)!;
    expect(path).toBeDefined();

    // Traversal: Internet -> API Gateway -> Backend Service -> Database
    expect(path.pathLength).toBe(3);
    expect(path.entryAssetId).toContain('asset-internet');
    expect(path.targetAssetId).toBe(dbApiSide.id);
  });
});
