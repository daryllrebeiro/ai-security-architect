import {
  createEvidence,
  type Asset,
  type Relationship,
  type Finding,
  type Evidence,
} from '@ai-security-architect/core';
import type {
  ContainerProvenanceConfig,
  ContainerProvenanceResult,
  ParsedDockerfileLineage,
} from './types.js';

export class ContainerLineageExtractor {
  public static parseDockerfile(
    dockerfileContent: string,
    dockerfilePath: string,
    serviceId: string,
    serviceName: string,
    workspaceFiles: string[] = []
  ): ParsedDockerfileLineage[] {
    const lines = dockerfileContent.split('\n');
    const results: ParsedDockerfileLineage[] = [];

    // Check for build integrity signals in repo files
    const hasSlsaProvenance = workspaceFiles.some(
      (f) =>
        f.toLowerCase().includes('.slsa-provenance') ||
        f.toLowerCase().includes('provenance.json') ||
        f.toLowerCase().includes('slsa-attestation')
    );

    const isCosignSigned = workspaceFiles.some(
      (f) =>
        f.toLowerCase().endsWith('.cosign.sig') ||
        f.toLowerCase().endsWith('.sig') ||
        f.toLowerCase().includes('cosign.bundle')
    );

    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line.toUpperCase().startsWith('FROM ')) {
        continue;
      }

      // e.g. "FROM --platform=linux/amd64 node:18-alpine AS builder"
      // or "FROM 123456789.dkr.ecr.us-east-1.amazonaws.com/base:latest"
      // or "FROM alpine@sha256:abcd..."
      const parts = line.split(/\s+/).filter((p) => !p.startsWith('--'));
      if (parts.length < 2) continue;

      const imageRef = parts[1];
      if (imageRef.startsWith('$') || imageRef === 'scratch') {
        continue; // skip build args or scratch
      }

      let registry: string | undefined = undefined;
      let baseImage = imageRef;
      let tag: string | undefined = undefined;
      let digest: string | undefined = undefined;

      // Extract digest if present
      if (imageRef.includes('@')) {
        const [img, dig] = imageRef.split('@');
        baseImage = img;
        digest = dig;
      }

      // Extract tag if present (and not swallowed by digest)
      if (baseImage.includes(':')) {
        const [img, t] = baseImage.split(':');
        baseImage = img;
        tag = t;
      } else if (!digest) {
        tag = 'latest'; // Docker defaults untagged images to latest
      }

      // Extract registry
      const firstSlash = baseImage.indexOf('/');
      if (firstSlash !== -1) {
        const possibleHost = baseImage.substring(0, firstSlash);
        if (possibleHost.includes('.') || possibleHost.includes(':') || possibleHost === 'localhost') {
          registry = possibleHost;
        }
      }
      if (!registry) {
        registry = 'docker.io';
      }

      const isDigestPinned = Boolean(digest && digest.startsWith('sha256:'));
      const isFloatingTag = !isDigestPinned && (tag === 'latest' || !tag || tag.startsWith('latest-'));

      results.push({
        serviceId,
        serviceName,
        dockerfilePath,
        baseImage: imageRef,
        tag,
        digest,
        registry,
        isDigestPinned,
        isFloatingTag,
        hasSlsaProvenance,
        isCosignSigned,
      });
    }

    return results;
  }

  public static analyze(
    lineages: ParsedDockerfileLineage[],
    tenantId: string,
    config: ContainerProvenanceConfig = {}
  ): ContainerProvenanceResult {
    const assets: Asset[] = [];
    const relationships: Relationship[] = [];
    const findings: Finding[] = [];
    const evidenceList: Evidence[] = [];

    const registryAllowlist = config.trustedRegistries && config.trustedRegistries.length > 0
      ? new Set(config.trustedRegistries.map((r) => r.toLowerCase()))
      : null;

    const seenAssets = new Set<string>();

    for (const lineage of lineages) {
      const sanitizedImg = lineage.baseImage.replace(/[^a-zA-Z0-9_-]/g, '_');
      const baseAssetId = `asset-image-base-${sanitizedImg}`;
      const registryAssetId = `asset-registry-${(lineage.registry || 'docker.io').replace(/[^a-zA-Z0-9_-]/g, '_')}`;

      // 1. Base image asset node
      if (!seenAssets.has(baseAssetId)) {
        seenAssets.add(baseAssetId);
        assets.push({
          id: baseAssetId,
          tenantId,
          type: 'CONTAINER_IMAGE',
          name: lineage.baseImage,
          environment: config.targetEnvironment ?? 'production',
          isPublic: lineage.registry === 'docker.io',
          isSensitiveData: false,
          criticality: 'MEDIUM',
          tags: ['container-image', 'base-image'],
          metadata: {
            tag: lineage.tag,
            digest: lineage.digest,
            registry: lineage.registry,
            isDigestPinned: lineage.isDigestPinned,
            isFloatingTag: lineage.isFloatingTag,
          },
        });
      }

      // 2. Registry asset node
      if (lineage.registry && !seenAssets.has(registryAssetId)) {
        seenAssets.add(registryAssetId);
        assets.push({
          id: registryAssetId,
          tenantId,
          type: 'REGISTRY',
          name: lineage.registry,
          environment: config.targetEnvironment ?? 'production',
          isPublic: lineage.registry === 'docker.io',
          isSensitiveData: false,
          criticality: 'LOW',
          tags: ['container-registry'],
          metadata: {
            isAllowlisted: registryAllowlist ? registryAllowlist.has(lineage.registry.toLowerCase()) : null,
          },
        });
      }

      // 3. Relationships
      // service DEPLOYED_AS container image
      relationships.push({
        id: `rel-deployed-as-${lineage.serviceId}-${baseAssetId}`,
        tenantId,
        sourceAssetId: lineage.serviceId,
        targetAssetId: baseAssetId,
        type: 'DEPLOYED_AS',
        nature: 'DECLARED',
        confidence: 1.0,
        metadata: { dockerfilePath: lineage.dockerfilePath },
      });

      // base image HOSTED_ON registry
      if (lineage.registry) {
        relationships.push({
          id: `rel-hosted-on-${baseAssetId}-${registryAssetId}`,
          tenantId,
          sourceAssetId: baseAssetId,
          targetAssetId: registryAssetId,
          type: 'HOSTED_ON',
          nature: 'DECLARED',
          confidence: 1.0,
          metadata: { registry: lineage.registry },
        });
      }

      const evidence = createEvidence({
        id: `ev-prov-${sanitizedImg}`,
        tenantId,
        sourceType: 'DOCKERFILE',
        repository: lineage.serviceName,
        filePath: lineage.dockerfilePath,
        lineStart: 1,
        lineEnd: 1,
        snippet: `FROM ${lineage.baseImage}`,
        scanner: 'ContainerLineageExtractor',
      });
      evidenceList.push(evidence);

      // 4. Findings
      // A: Floating tag finding
      if (lineage.isFloatingTag) {
        findings.push({
          id: `finding-floating-tag-${sanitizedImg}`,
          tenantId,
          assetId: baseAssetId,
          category: 'SUPPLY_CHAIN_INTEGRITY',
          ruleId: 'SEC-PROV-001',
          title: `Floating or Unpinned Container Base Image Tag: ${lineage.baseImage}`,
          description: `Base image '${lineage.baseImage}' in '${lineage.dockerfilePath}' uses a floating or unpinned tag ('${lineage.tag ?? 'latest'}'). Builds are nondeterministic and subject to silent upstream changes.`,
          severity: 'MEDIUM',
          confidence: 'HIGH',
          scanner: 'ContainerLineageExtractor',
          evidence,
          remediationRecommendation: `Pin the base image to an immutable digest (e.g. '${lineage.baseImage.split(':')[0]}@sha256:...').`,
          metadata: {
            tag: lineage.tag,
            isFloatingTag: true,
            isDigestPinned: false,
          },
        });
      }

      // B: Registry allowlist violation (ONLY if allowlist is configured)
      if (registryAllowlist && lineage.registry && !registryAllowlist.has(lineage.registry.toLowerCase())) {
        findings.push({
          id: `finding-untrusted-registry-${sanitizedImg}`,
          tenantId,
          assetId: baseAssetId,
          category: 'SUPPLY_CHAIN_INTEGRITY',
          ruleId: 'SEC-PROV-002',
          title: `Untrusted Container Image Registry: ${lineage.registry}`,
          description: `Base image '${lineage.baseImage}' is pulled from registry '${lineage.registry}', which is not present in the configured trusted registries allowlist (${Array.from(registryAllowlist).join(', ')}).`,
          severity: 'HIGH',
          confidence: 'HIGH',
          scanner: 'ContainerLineageExtractor',
          evidence,
          remediationRecommendation: `Migrate base image to an approved corporate registry (${Array.from(registryAllowlist).join(', ')}).`,
          metadata: {
            registry: lineage.registry,
            trustedRegistries: Array.from(registryAllowlist),
          },
        });
      }

      // C: Build integrity / attestation check for production deployments
      const isProduction = (config.targetEnvironment ?? 'production') === 'production';
      if (isProduction && !lineage.hasSlsaProvenance && !lineage.isCosignSigned) {
        findings.push({
          id: `finding-unattested-image-${sanitizedImg}`,
          tenantId,
          assetId: baseAssetId,
          category: 'SUPPLY_CHAIN_INTEGRITY',
          ruleId: 'SEC-PROV-003',
          title: `Unsigned or Unattested Production Container Deployment: ${lineage.baseImage}`,
          description: `Container image '${lineage.baseImage}' is designated for production but lacks cryptographic build attestations (SLSA provenance or Cosign signature).`,
          severity: 'MEDIUM',
          confidence: 'HIGH',
          scanner: 'ContainerLineageExtractor',
          evidence,
          remediationRecommendation: 'Implement Cosign keyless signing and SLSA provenance attestation in your CI/CD build pipeline.',
          metadata: {
            hasSlsaProvenance: lineage.hasSlsaProvenance,
            isCosignSigned: lineage.isCosignSigned,
          },
        });
      }
    }

    return { assets, relationships, findings, evidence: evidenceList };
  }
}
