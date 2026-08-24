import {
  createEvidence,
  type Asset,
  type Relationship,
  type Evidence,
} from '@ai-security-architect/core';
import type { DiscoveryContext, DiscoveryExtractor, DiscoveryResult } from '../types.js';
import type { EphemeralWorkspace } from '@ai-security-architect/ingestion';

export class DependencyExtractor implements DiscoveryExtractor {
  public readonly name = 'DependencyExtractor';

  public async supports(_workspace: EphemeralWorkspace, fileList: string[]): Promise<boolean> {
    return fileList.some(
      (f) =>
        f.endsWith('pom.xml') ||
        f.endsWith('package.json') ||
        f.endsWith('requirements.txt')
    );
  }

  public async extract(context: DiscoveryContext, fileList: string[]): Promise<DiscoveryResult> {
    const assets: Asset[] = [];
    const relationships: Relationship[] = [];
    const evidenceList: Evidence[] = [];

    // Parse package.json
    const packageJsonFiles = fileList.filter((f) => f.endsWith('package.json') && !f.includes('node_modules'));

    for (const filePath of packageJsonFiles) {
      let content: string;
      try {
        content = await context.workspace.readSafeFile(filePath);
        const pkg = JSON.parse(content);

        const allDeps = {
          ...(pkg.dependencies || {}),
          ...(pkg.devDependencies || {}),
        };

        const evidence = createEvidence({
          id: `ev-pkg-${filePath.replace(/[^a-zA-Z0-9]/g, '_')}`,
          tenantId: context.tenantId,
          sourceType: 'DEPENDENCY_LOCKFILE',
          repository: context.repository,
          filePath,
          lineStart: 1,
          lineEnd: content.split('\n').length,
          snippet: content,
          scanner: 'DependencyExtractor',
        });
        evidenceList.push(evidence);

        for (const [depName, version] of Object.entries(allDeps)) {
          const depAssetId = `asset-dep-npm-${depName.replace(/[^a-zA-Z0-9]/g, '_')}`;

          assets.push({
            id: depAssetId,
            tenantId: context.tenantId,
            type: 'DEPENDENCY',
            name: depName,
            environment: 'npm',
            isPublic: false,
            isSensitiveData: false,
            criticality: 'LOW',
            metadata: {
              ecosystem: 'npm',
              version: String(version),
              manifestPath: filePath,
            },
            tags: ['dependency', 'npm'],
          });
        }
      } catch {
        continue;
      }
    }

    // Parse pom.xml
    const pomFiles = fileList.filter((f) => f.endsWith('pom.xml'));

    for (const filePath of pomFiles) {
      let content: string;
      try {
        content = await context.workspace.readSafeFile(filePath);
        const depRegex = /<dependency>[\s\S]*?<groupId>([^<]+)<\/groupId>[\s\S]*?<artifactId>([^<]+)<\/artifactId>[\s\S]*?(?:<version>([^<]+)<\/version>)?[\s\S]*?<\/dependency>/g;
        let match: RegExpExecArray | null;

        while ((match = depRegex.exec(content)) !== null) {
          const groupId = match[1].trim();
          const artifactId = match[2].trim();
          const version = match[3] ? match[3].trim() : 'inherited';

          const depName = `${groupId}:${artifactId}`;
          const depAssetId = `asset-dep-mvn-${groupId.replace(/[^a-zA-Z0-9]/g, '_')}-${artifactId.replace(/[^a-zA-Z0-9]/g, '_')}`;

          assets.push({
            id: depAssetId,
            tenantId: context.tenantId,
            type: 'DEPENDENCY',
            name: depName,
            environment: 'maven',
            isPublic: false,
            isSensitiveData: false,
            criticality: 'LOW',
            metadata: {
              ecosystem: 'maven',
              groupId,
              artifactId,
              version,
              manifestPath: filePath,
            },
            tags: ['dependency', 'maven'],
          });
        }
      } catch {
        continue;
      }
    }

    return { assets, relationships, evidence: evidenceList };
  }
}
