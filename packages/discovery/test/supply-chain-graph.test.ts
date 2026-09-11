import { describe, it, expect } from 'vitest';
import { DependencyExtractor } from '../src/extractors/dependency-extractor.js';
import { DiscoveryEngine } from '../src/discovery-engine.js';
import type { EphemeralWorkspace } from '@ai-security-architect/ingestion';
import type { DiscoveryContext } from '../src/types.js';

describe('Task C.1 — Dependency & Supply-Chain Graph Layer', () => {
  const tenantId = 'tenant-supply-chain-test';
  const repository = 'enterprise/auth-service';

  function createMockWorkspace(files: Record<string, string>): EphemeralWorkspace {
    return {
      workspaceDir: '/mock/workspace',
      tenantId,
      repository,
      commitSha: 'mock-sha',
      readSafeFile: async (filePath: string) => {
        if (files[filePath]) return files[filePath];
        throw new Error(`File not found: ${filePath}`);
      },
      listFilesSafe: async () => Object.keys(files),
      cleanup: async () => {},
    } as unknown as EphemeralWorkspace;
  }

  it('extracts npm lockfile packages and overlays CVE advisory findings for vulnerable versions', async () => {
    const extractor = new DependencyExtractor();

    const packageLockContent = JSON.stringify({
      name: 'auth-service',
      version: '1.0.0',
      lockfileVersion: 3,
      packages: {
        '': { name: 'auth-service', version: '1.0.0' },
        'node_modules/jsonwebtoken': {
          version: '8.5.1', // Vulnerable to CVE-2022-23529 (< 9.0.0)
        },
        'node_modules/express': {
          version: '4.19.2',
        },
      },
    });

    const workspace = createMockWorkspace({
      'package-lock.json': packageLockContent,
    });

    const context: DiscoveryContext = { tenantId, repository, workspace };
    const result = await extractor.extract(context, ['package-lock.json']);

    expect(result.assets.length).toBe(2);

    const jwtAsset = result.assets.find((a) => a.name === 'jsonwebtoken');
    expect(jwtAsset).toBeDefined();
    expect(jwtAsset?.type).toBe('DEPENDENCY');
    expect(jwtAsset?.criticality).toBe('HIGH');
    expect(jwtAsset?.tags).toContain('vulnerable');
    expect(jwtAsset?.tags).toContain('cve:CVE-2022-23529');

    // Findings overlay check
    expect(result.findings?.length).toBe(1);
    const finding = result.findings?.[0];
    expect(finding?.assetId).toBe(jwtAsset?.id);
    expect(finding?.category).toBe('VULNERABLE_DEPENDENCY');
    expect(finding?.title).toContain('CVE-2022-23529');
    expect(finding?.severity).toBe('HIGH');
  });

  it('extracts Maven pom.xml and detects Log4Shell (CVE-2021-44228)', async () => {
    const extractor = new DependencyExtractor();

    const pomXmlContent = `
    <project>
      <dependencies>
        <dependency>
          <groupId>org.apache.logging.log4j</groupId>
          <artifactId>log4j-core</artifactId>
          <version>2.14.1</version>
        </dependency>
      </dependencies>
    </project>
    `;

    const workspace = createMockWorkspace({
      'pom.xml': pomXmlContent,
    });

    const context: DiscoveryContext = { tenantId, repository, workspace };
    const result = await extractor.extract(context, ['pom.xml']);

    expect(result.assets.length).toBe(1);
    const log4jAsset = result.assets[0];
    expect(log4jAsset.name).toBe('org.apache.logging.log4j:log4j-core');
    expect(log4jAsset.criticality).toBe('CRITICAL');
    expect(log4jAsset.tags).toContain('cve:CVE-2021-44228');

    expect(result.findings?.length).toBe(1);
    expect(result.findings?.[0].title).toContain('Log4Shell');
  });

  it('links workloads to discovered dependencies via DEPENDS_ON relationships in DiscoveryEngine', async () => {
    const pomXml = `
    <project>
      <dependencies>
        <dependency>
          <groupId>org.apache.logging.log4j</groupId>
          <artifactId>log4j-core</artifactId>
          <version>2.14.1</version>
        </dependency>
      </dependencies>
    </project>`;

    const k8sManifest = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payment-deployment
spec:
  template:
    metadata:
      labels:
        app: payment-service
    spec:
      containers:
      - name: payment-app
        image: payment:1.0.0
`;

    const workspace = createMockWorkspace({
      'pom.xml': pomXml,
      'deployment.yaml': k8sManifest,
    });

    const engine = new DiscoveryEngine();
    const context: DiscoveryContext = { tenantId, repository, workspace };

    const result = await engine.discover(context);

    // Verify assets
    const dep = result.assets.find((a) => a.type === 'DEPENDENCY');
    expect(dep).toBeDefined();

    // Verify DEPENDS_ON relationship from pod/service to dependency
    const dependsOnRel = result.relationships.find(
      (r) => r.type === 'DEPENDS_ON' && r.targetAssetId === dep?.id
    );
    expect(dependsOnRel).toBeDefined();
    expect(dependsOnRel?.nature).toBe('DECLARED');

    // Verify COMPROMISES relationship from vulnerable dependency to pod
    const compromisesRel = result.relationships.find(
      (r) => r.type === 'COMPROMISES' && r.sourceAssetId === dep?.id
    );
    expect(compromisesRel).toBeDefined();
    expect(compromisesRel?.nature).toBe('INFERRED');
  });

  it('enables AttackPathEngine to discover multi-hop attack paths through vulnerable dependencies', async () => {
    const { SecurityGraphEngine } = await import('@ai-security-architect/graph');
    const { AttackPathEngine } = await import('@ai-security-architect/attackpath');
    const typeModule = await import('@ai-security-architect/core');

    const graph = new SecurityGraphEngine(tenantId);

    const internet: any = {
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

    const alb: any = {
      id: 'asset-alb',
      tenantId,
      type: 'LOAD_BALANCER',
      name: 'api-gateway',
      environment: 'production',
      isPublic: true,
      isSensitiveData: false,
      criticality: 'MEDIUM',
      metadata: {},
      tags: [],
    };

    const service: any = {
      id: 'asset-svc',
      tenantId,
      type: 'SERVICE',
      name: 'payment-svc',
      environment: 'production',
      isPublic: false,
      isSensitiveData: false,
      criticality: 'HIGH',
      metadata: {},
      tags: [],
    };

    const depLog4j: any = {
      id: 'asset-dep-log4j',
      tenantId,
      type: 'DEPENDENCY',
      name: 'org.apache.logging.log4j:log4j-core',
      environment: 'maven',
      isPublic: false,
      isSensitiveData: false,
      criticality: 'CRITICAL',
      metadata: {},
      tags: ['dependency', 'vulnerable', 'cve:CVE-2021-44228'],
    };

    const pod: any = {
      id: 'asset-pod',
      tenantId,
      type: 'POD',
      name: 'payment-pod',
      environment: 'production',
      isPublic: false,
      isSensitiveData: false,
      criticality: 'HIGH',
      metadata: {},
      tags: [],
    };

    const role: any = {
      id: 'asset-role',
      tenantId,
      type: 'IAM_ROLE',
      name: 'vault-access-role',
      environment: 'production',
      isPublic: false,
      isSensitiveData: false,
      criticality: 'CRITICAL',
      metadata: {},
      tags: [],
    };

    const db: any = {
      id: 'asset-db-vault',
      tenantId,
      type: 'DATABASE',
      name: 'customer-vault',
      environment: 'production',
      isPublic: false,
      isSensitiveData: true,
      criticality: 'CRITICAL',
      metadata: {},
      tags: ['contains-pii'],
    };

    graph.addAsset(internet);
    graph.addAsset(alb);
    graph.addAsset(service);
    graph.addAsset(depLog4j);
    graph.addAsset(pod);
    graph.addAsset(role);
    graph.addAsset(db);

    // Multi-hop path: Internet -> ALB -> SVC -> DEP (Log4Shell) -> POD -> ROLE -> DB
    graph.addRelationship({
      id: 'rel-inet-alb',
      tenantId,
      sourceAssetId: internet.id,
      targetAssetId: alb.id,
      type: 'EXPOSES_HTTP',
      confidence: 1.0,
      nature: 'DECLARED',
      metadata: {},
    });

    graph.addRelationship({
      id: 'rel-alb-svc',
      tenantId,
      sourceAssetId: alb.id,
      targetAssetId: service.id,
      type: 'ROUTES_TO',
      confidence: 1.0,
      nature: 'DECLARED',
      metadata: {},
    });

    graph.addRelationship({
      id: 'rel-svc-dep',
      tenantId,
      sourceAssetId: service.id,
      targetAssetId: depLog4j.id,
      type: 'DEPENDS_ON',
      confidence: 1.0,
      nature: 'DECLARED',
      metadata: {},
    });

    graph.addRelationship({
      id: 'rel-dep-pod',
      tenantId,
      sourceAssetId: depLog4j.id,
      targetAssetId: pod.id,
      type: 'COMPROMISES',
      confidence: 1.0,
      nature: 'INFERRED',
      metadata: {},
    });

    graph.addRelationship({
      id: 'rel-pod-role',
      tenantId,
      sourceAssetId: pod.id,
      targetAssetId: role.id,
      type: 'ASSUMES_ROLE',
      confidence: 1.0,
      nature: 'DECLARED',
      metadata: {},
    });

    graph.addRelationship({
      id: 'rel-role-db',
      tenantId,
      sourceAssetId: role.id,
      targetAssetId: db.id,
      type: 'CAN_READ',
      confidence: 1.0,
      nature: 'DECLARED',
      metadata: {},
    });

    const engine = new AttackPathEngine();
    const paths = engine.analyzePaths(graph);

    expect(paths.length).toBeGreaterThan(0);
    const supplyChainPath = paths.find((p) =>
      p.steps.some((s) => s.targetAssetId === 'asset-dep-log4j')
    );

    expect(supplyChainPath).toBeDefined();
    expect(supplyChainPath?.entryAssetId).toBe('asset-internet');
    expect(supplyChainPath?.targetAssetId).toBe('asset-db-vault');

    // Confirm step explanations reflect software dependency import and compromise
    const depStep = supplyChainPath?.steps.find((s) => s.relationshipType === 'DEPENDS_ON');
    expect(depStep?.explanation).toContain('imports software dependency');

    const compStep = supplyChainPath?.steps.find((s) => s.relationshipType === 'COMPROMISES');
    expect(compStep?.explanation).toContain('grants remote code execution');
  });
});
