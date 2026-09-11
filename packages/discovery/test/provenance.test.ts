import { describe, it, expect } from 'vitest';
import {
  CycloneDxGenerator,
  SpdxGenerator,
  ContainerLineageExtractor,
  type DiscoveredDependency,
} from '../src/index.js';

describe('Task D.1 — SBOM Generation & Container Image Provenance', () => {
  const sampleDeps: DiscoveredDependency[] = [
    {
      name: 'express',
      version: '4.18.2',
      ecosystem: 'npm',
      license: 'MIT',
      isDirect: true,
      purl: 'pkg:npm/express@4.18.2',
      dependencies: ['qs@6.11.0'],
    },
    {
      name: 'qs',
      version: '6.11.0',
      ecosystem: 'npm',
      license: 'BSD-3-Clause',
      isDirect: false,
      purl: 'pkg:npm/qs@6.11.0',
    },
    {
      name: 'org.springframework.boot:spring-boot-starter-web',
      version: '3.1.0',
      ecosystem: 'maven',
      license: 'Apache-2.0',
      isDirect: true,
      purl: 'pkg:maven/org.springframework.boot/spring-boot-starter-web@3.1.0',
    },
  ];

  describe('CycloneDX 1.5 JSON SBOM Generation', () => {
    it('generates standards-compliant CycloneDX 1.5 JSON with components, licenses, and PURLs', () => {
      const bom = CycloneDxGenerator.generate(sampleDeps, {
        serviceName: 'order-service',
        version: '2.4.0',
        timestamp: '2026-09-11T12:00:00Z',
      });

      expect(bom.bomFormat).toBe('CycloneDX');
      expect(bom.specVersion).toBe('1.5');
      expect(bom.serialNumber).toMatch(/^urn:uuid:[a-f0-9-]+$/);
      expect(bom.metadata.component.name).toBe('order-service');
      expect(bom.metadata.component.version).toBe('2.4.0');

      expect(bom.components).toHaveLength(3);
      const expressComp = bom.components.find((c) => c.name === 'express');
      expect(expressComp).toBeDefined();
      expect(expressComp?.version).toBe('4.18.2');
      expect(expressComp?.purl).toBe('pkg:npm/express@4.18.2');
      expect(expressComp?.licenses?.[0]?.license?.id).toBe('MIT');
      expect(expressComp?.scope).toBe('required');

      const qsComp = bom.components.find((c) => c.name === 'qs');
      expect(qsComp?.scope).toBe('optional');

      const json = CycloneDxGenerator.generateJson(sampleDeps, { serviceName: 'order-service' });
      const parsed = JSON.parse(json);
      expect(parsed.bomFormat).toBe('CycloneDX');
    });
  });

  describe('SPDX 2.3 JSON SBOM Generation', () => {
    it('generates standards-compliant SPDX 2.3 JSON with packages and relationships', () => {
      const doc = SpdxGenerator.generate(sampleDeps, {
        serviceName: 'order-service',
        timestamp: '2026-09-11T12:00:00Z',
      });

      expect(doc.spdxVersion).toBe('SPDX-2.3');
      expect(doc.dataLicense).toBe('CC0-1.0');
      expect(doc.SPDXID).toBe('SPDXRef-DOCUMENT');
      expect(doc.name).toBe('order-service');
      expect(doc.packages).toHaveLength(3);

      const expressPkg = doc.packages.find((p) => p.name === 'express');
      expect(expressPkg).toBeDefined();
      expect(expressPkg?.versionInfo).toBe('4.18.2');
      expect(expressPkg?.licenseDeclared).toBe('MIT');
      expect(expressPkg?.licenseConcluded).toBe('MIT');
      expect(expressPkg?.externalRefs?.[0]?.referenceLocator).toBe('pkg:npm/express@4.18.2');

      expect(doc.relationships).toHaveLength(3);
      expect(doc.relationships[0].relationshipType).toBe('DESCRIBES');

      const json = SpdxGenerator.generateJson(sampleDeps, { serviceName: 'order-service' });
      const parsed = JSON.parse(json);
      expect(parsed.spdxVersion).toBe('SPDX-2.3');
    });
  });

  describe('Container Image Lineage & Build Integrity', () => {
    it('flags floating tag base images while digest-pinned base images are not flagged', () => {
      const floatingDockerfile = `
        FROM node:latest AS builder
        WORKDIR /app
        COPY . .
      `;

      const pinnedDockerfile = `
        FROM node@sha256:711e3b603388a1b559ba9c719e7ddb54e8ec6be82bb2b45e9ea2716e91ea6b60
        WORKDIR /app
      `;

      const floatingLineages = ContainerLineageExtractor.parseDockerfile(
        floatingDockerfile,
        'Dockerfile.floating',
        'svc-order',
        'order-service',
        ['.slsa-provenance.json']
      );
      const pinnedLineages = ContainerLineageExtractor.parseDockerfile(
        pinnedDockerfile,
        'Dockerfile.pinned',
        'svc-order',
        'order-service',
        ['.slsa-provenance.json']
      );

      const floatingResult = ContainerLineageExtractor.analyze(floatingLineages, 'tenant-01');
      const pinnedResult = ContainerLineageExtractor.analyze(pinnedLineages, 'tenant-01');

      const floatingFindings = floatingResult.findings.filter((f) => f.ruleId === 'SEC-PROV-001');
      const pinnedFindings = pinnedResult.findings.filter((f) => f.ruleId === 'SEC-PROV-001');

      expect(floatingFindings).toHaveLength(1);
      expect(floatingFindings[0].category).toBe('SUPPLY_CHAIN_INTEGRITY');
      expect(floatingFindings[0].title).toContain('Floating or Unpinned');

      expect(pinnedFindings).toHaveLength(0);
    });

    it('enforces registry allowlists when configured, and emits no finding when no allowlist is configured', () => {
      const untrustedDockerfile = `
        FROM untrusted-reg.evil.com/app/base:v1.2.0
      `;

      const lineages = ContainerLineageExtractor.parseDockerfile(
        untrustedDockerfile,
        'Dockerfile',
        'svc-payment',
        'payment-service',
        ['release.sig']
      );

      // Scenario A: Allowlist configured
      const restrictedResult = ContainerLineageExtractor.analyze(lineages, 'tenant-01', {
        trustedRegistries: ['ecr.aws', 'gcr.io', '123456.dkr.ecr.us-east-1.amazonaws.com'],
      });
      const regFindings = restrictedResult.findings.filter((f) => f.ruleId === 'SEC-PROV-002');
      expect(regFindings).toHaveLength(1);
      expect(regFindings[0].category).toBe('SUPPLY_CHAIN_INTEGRITY');
      expect(regFindings[0].title).toContain('Untrusted Container Image Registry');

      // Scenario B: No allowlist configured (default behavior: do not invent unrequested policy)
      const permissiveResult = ContainerLineageExtractor.analyze(lineages, 'tenant-01', {
        trustedRegistries: [],
      });
      const noRegFindings = permissiveResult.findings.filter((f) => f.ruleId === 'SEC-PROV-002');
      expect(noRegFindings).toHaveLength(0);
    });

    it('surfaces unsigned/unattested production container deployments as distinct supply-chain integrity findings', () => {
      const dockerfile = `
        FROM gcr.io/corp/base@sha256:711e3b603388a1b559ba9c719e7ddb54e8ec6be82bb2b45e9ea2716e91ea6b60
      `;

      // Production without attestations
      const unsignedLineages = ContainerLineageExtractor.parseDockerfile(
        dockerfile,
        'Dockerfile',
        'svc-core',
        'core-service',
        ['package.json'] // No .slsa-provenance.json or .cosign.sig
      );

      const result = ContainerLineageExtractor.analyze(unsignedLineages, 'tenant-01', {
        targetEnvironment: 'production',
        trustedRegistries: ['gcr.io'],
      });

      const integrityFinding = result.findings.find((f) => f.ruleId === 'SEC-PROV-003');
      expect(integrityFinding).toBeDefined();
      expect(integrityFinding?.category).toBe('SUPPLY_CHAIN_INTEGRITY');
      expect(integrityFinding?.title).toContain('Unsigned or Unattested');

      // Verify asset graph nodes and relationships
      const imageAsset = result.assets.find((a) => a.type === 'CONTAINER_IMAGE');
      const registryAsset = result.assets.find((a) => a.type === 'REGISTRY');
      expect(imageAsset).toBeDefined();
      expect(registryAsset).toBeDefined();

      const builtFromRel = result.relationships.find((r) => r.type === 'DEPLOYED_AS');
      const hostedOnRel = result.relationships.find((r) => r.type === 'HOSTED_ON');
      expect(builtFromRel).toBeDefined();
      expect(hostedOnRel).toBeDefined();
    });
  });
});
