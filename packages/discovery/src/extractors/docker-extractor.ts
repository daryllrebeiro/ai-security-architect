import {
  createEvidence,
  type Asset,
  type Relationship,
  type Evidence,
} from '@ai-security-architect/core';
import type { DiscoveryContext, DiscoveryExtractor, DiscoveryResult } from '../types.js';
import type { EphemeralWorkspace } from '@ai-security-architect/ingestion';

export class DockerExtractor implements DiscoveryExtractor {
  public readonly name = 'DockerExtractor';

  public async supports(_workspace: EphemeralWorkspace, fileList: string[]): Promise<boolean> {
    return fileList.some((f) => f.toLowerCase().includes('dockerfile'));
  }

  public async extract(context: DiscoveryContext, fileList: string[]): Promise<DiscoveryResult> {
    const assets: Asset[] = [];
    const relationships: Relationship[] = [];
    const evidenceList: Evidence[] = [];

    const dockerfiles = fileList.filter((f) => f.toLowerCase().endsWith('dockerfile') || f.toLowerCase().includes('dockerfile'));

    for (const filePath of dockerfiles) {
      let content: string;
      try {
        content = await context.workspace.readSafeFile(filePath);
      } catch {
        continue;
      }

      const lines = content.split('\n');
      const fromLine = lines.find((l) => l.trim().toUpperCase().startsWith('FROM '));
      const baseImage = fromLine ? fromLine.trim().split(/\s+/)[1] : 'unknown';

      const exposedPorts = lines
        .filter((l) => l.trim().toUpperCase().startsWith('EXPOSE '))
        .map((l) => l.trim().split(/\s+/)[1]);

      const userLine = lines.find((l) => l.trim().toUpperCase().startsWith('USER '));
      const isRoot = !userLine || userLine.includes('root') || userLine.includes('0');

      const containerName = filePath.replace(/[\/\\]/g, '-').replace(/dockerfile/i, 'container').replace(/^-+/, '') || 'app-container';
      const containerId = `asset-container-${containerName}`;

      const evidence = createEvidence({
        id: `ev-docker-${containerId}`,
        tenantId: context.tenantId,
        sourceType: 'DOCKERFILE',
        repository: context.repository,
        filePath,
        lineStart: 1,
        lineEnd: lines.length,
        snippet: content,
        scanner: 'DockerExtractor',
      });
      evidenceList.push(evidence);

      assets.push({
        id: containerId,
        tenantId: context.tenantId,
        type: 'CONTAINER',
        name: containerName,
        environment: 'container-runtime',
        isPublic: false,
        isSensitiveData: false,
        criticality: 'MEDIUM',
        metadata: {
          baseImage,
          exposedPorts,
          runsAsRoot: isRoot,
          filePath,
        },
        tags: ['container', 'docker', isRoot ? 'root-user' : 'non-root'],
      });
    }

    return { assets, relationships, evidence: evidenceList };
  }
}
