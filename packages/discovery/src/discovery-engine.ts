import type { Asset, Relationship, Evidence } from '@ai-security-architect/core';
import type { EphemeralWorkspace } from '@ai-security-architect/ingestion';
import type { DiscoveryContext, DiscoveryExtractor, DiscoveryResult } from './types.js';
import { JavaSpringExtractor } from './extractors/java-spring-extractor.js';
import { KubernetesExtractor } from './extractors/kubernetes-extractor.js';
import { TerraformExtractor } from './extractors/terraform-extractor.js';
import { DockerExtractor } from './extractors/docker-extractor.js';
import { DependencyExtractor } from './extractors/dependency-extractor.js';

export class DiscoveryEngine {
  private readonly extractors: DiscoveryExtractor[];

  constructor(extractors?: DiscoveryExtractor[]) {
    this.extractors = extractors ?? [
      new JavaSpringExtractor(),
      new KubernetesExtractor(),
      new TerraformExtractor(),
      new DockerExtractor(),
      new DependencyExtractor(),
    ];
  }

  public async discover(context: DiscoveryContext): Promise<DiscoveryResult> {
    const fileList = await context.workspace.listFilesSafe();

    const assetsMap = new Map<string, Asset>();
    const relationshipsMap = new Map<string, Relationship>();
    const evidenceMap = new Map<string, Evidence>();

    for (const extractor of this.extractors) {
      const isSupported = await extractor.supports(context.workspace, fileList);
      if (!isSupported) {
        continue;
      }

      try {
        const result = await extractor.extract(context, fileList);

        for (const asset of result.assets) {
          assetsMap.set(asset.id, asset);
        }

        for (const rel of result.relationships) {
          relationshipsMap.set(rel.id, rel);
        }

        for (const ev of result.evidence) {
          evidenceMap.set(ev.id, ev);
        }
      } catch (err: unknown) {
        // Continue other extractors on non-fatal extractor error
        console.warn(`[DiscoveryEngine] Extractor "${extractor.name}" failed: ${(err as Error).message}`);
      }
    }

    // Cross-Layer Linkage Post-Processing
    this.linkCrossLayerEntities(context.tenantId, assetsMap, relationshipsMap);

    return {
      assets: Array.from(assetsMap.values()),
      relationships: Array.from(relationshipsMap.values()),
      evidence: Array.from(evidenceMap.values()),
    };
  }

  private linkCrossLayerEntities(
    tenantId: string,
    assets: Map<string, Asset>,
    relationships: Map<string, Relationship>
  ): void {
    const allAssets = Array.from(assets.values());

    // 1. Link Load Balancers (ALB) -> Services
    const loadBalancers = allAssets.filter((a) => a.type === 'LOAD_BALANCER');
    const services = allAssets.filter((a) => a.type === 'SERVICE');

    for (const lb of loadBalancers) {
      for (const svc of services) {
        const relId = `rel-${lb.id}-${svc.id}`;
        if (!relationships.has(relId)) {
          relationships.set(relId, {
            id: relId,
            tenantId,
            sourceAssetId: lb.id,
            targetAssetId: svc.id,
            type: 'ROUTES_TO',
            nature: 'INFERRED',
            confidence: 0.9,
            metadata: { description: 'Load balancer target group routes to microservice' },
          });
        }
      }
    }

    // 2. Link Services -> Pods
    const pods = allAssets.filter((a) => a.type === 'POD');
    for (const svc of services) {
      for (const pod of pods) {
        const relId = `rel-${svc.id}-${pod.id}`;
        if (!relationships.has(relId)) {
          relationships.set(relId, {
            id: relId,
            tenantId,
            sourceAssetId: svc.id,
            targetAssetId: pod.id,
            type: 'DEPLOYED_TO',
            nature: 'INFERRED',
            confidence: 0.95,
            metadata: { description: 'Microservice runs in Kubernetes Pod' },
          });
        }
      }
    }
  }
}
