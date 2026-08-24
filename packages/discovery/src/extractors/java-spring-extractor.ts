import {
  createEvidence,
  type Asset,
  type Relationship,
  type Evidence,
} from '@ai-security-architect/core';
import type { DiscoveryContext, DiscoveryExtractor, DiscoveryResult } from '../types.js';
import type { EphemeralWorkspace } from '@ai-security-architect/ingestion';

export class JavaSpringExtractor implements DiscoveryExtractor {
  public readonly name = 'JavaSpringExtractor';

  public async supports(_workspace: EphemeralWorkspace, fileList: string[]): Promise<boolean> {
    return fileList.some((f) => f.endsWith('.java') || f.endsWith('pom.xml') || f.endsWith('build.gradle'));
  }

  public async extract(context: DiscoveryContext, fileList: string[]): Promise<DiscoveryResult> {
    const assets: Asset[] = [];
    const relationships: Relationship[] = [];
    const evidenceList: Evidence[] = [];

    const javaFiles = fileList.filter((f) => f.endsWith('.java'));

    for (const filePath of javaFiles) {
      let content: string;
      try {
        content = await context.workspace.readSafeFile(filePath);
      } catch {
        continue;
      }

      if (!content.includes('@RestController') && !content.includes('@Controller')) {
        continue;
      }

      const lines = content.split('\n');

      // Extract class name
      const classMatch = content.match(/public\s+class\s+(\w+)/);
      const className = classMatch ? classMatch[1] : 'SpringController';

      // Extract class level @RequestMapping
      let basePath = '';
      const classReqMatch = content.match(/@RequestMapping\(\s*(?:value\s*=\s*)?["']([^"']+)["']\s*\)/);
      if (classReqMatch) {
        basePath = classReqMatch[1].startsWith('/') ? classReqMatch[1] : `/${classReqMatch[1]}`;
      }

      const controllerAssetId = `asset-ctrl-${className.toLowerCase()}`;
      const serviceName = className.toLowerCase().replace('controller', '') || 'spring-service';
      const serviceAssetId = `asset-svc-${serviceName}`;

      // Register Service Asset
      assets.push({
        id: serviceAssetId,
        tenantId: context.tenantId,
        type: 'SERVICE',
        name: `${serviceName}-service`,
        environment: 'production',
        isPublic: false,
        isSensitiveData: false,
        criticality: 'HIGH',
        metadata: {
          framework: 'spring-boot',
          language: 'java',
          primaryController: className,
        },
        tags: ['backend', 'spring-boot'],
      });

      // Register Controller Asset
      assets.push({
        id: controllerAssetId,
        tenantId: context.tenantId,
        type: 'API_CONTROLLER',
        name: className,
        environment: 'production',
        isPublic: false,
        isSensitiveData: false,
        criticality: 'MEDIUM',
        metadata: {
          filePath,
          basePath,
        },
        tags: ['spring-controller'],
      });

      // Relationship Service -> Controller
      relationships.push({
        id: `rel-${serviceAssetId}-${controllerAssetId}`,
        tenantId: context.tenantId,
        sourceAssetId: serviceAssetId,
        targetAssetId: controllerAssetId,
        type: 'CONTAINS',
        nature: 'DECLARED',
        confidence: 1.0,
        metadata: {},
      });

      // Scan lines for endpoint annotations
      const httpAnnotations = [
        { regex: /@GetMapping\(\s*(?:value\s*=\s*)?["']?([^"'\)]*)["']?\s*\)/, method: 'GET' },
        { regex: /@PostMapping\(\s*(?:value\s*=\s*)?["']?([^"'\)]*)["']?\s*\)/, method: 'POST' },
        { regex: /@PutMapping\(\s*(?:value\s*=\s*)?["']?([^"'\)]*)["']?\s*\)/, method: 'PUT' },
        { regex: /@DeleteMapping\(\s*(?:value\s*=\s*)?["']?([^"'\)]*)["']?\s*\)/, method: 'DELETE' },
        { regex: /@PatchMapping\(\s*(?:value\s*=\s*)?["']?([^"'\)]*)["']?\s*\)/, method: 'PATCH' },
        { regex: /@RequestMapping\(\s*(?:value\s*=\s*)?["']?([^"'\)]*)["']?\s*\)/, method: 'ALL' },
      ];

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        for (const ann of httpAnnotations) {
          const match = line.match(ann.regex);
          if (match) {
            let subPath = match[1] || '';
            if (subPath && !subPath.startsWith('/')) {
              subPath = `/${subPath}`;
            }

            const fullPath = `${basePath}${subPath}` || '/';
            const endpointId = `asset-endpoint-${serviceName}-${ann.method.toLowerCase()}-${fullPath.replace(/[^a-zA-Z0-9]/g, '_')}`;

            // Find end of method or capture line window
            const lineStart = i + 1;
            const lineEnd = Math.min(lines.length, lineStart + 15);
            const snippet = lines.slice(i, lineEnd).join('\n');

            const evidence = createEvidence({
              id: `ev-endpoint-${endpointId}`,
              tenantId: context.tenantId,
              sourceType: 'SOURCE_CODE',
              repository: context.repository,
              filePath,
              lineStart,
              lineEnd,
              snippet,
              scanner: 'JavaSpringExtractor',
            });

            evidenceList.push(evidence);

            assets.push({
              id: endpointId,
              tenantId: context.tenantId,
              type: 'ENDPOINT',
              name: fullPath,
              environment: 'production',
              isPublic: false,
              isSensitiveData: false,
              criticality: 'MEDIUM',
              metadata: {
                httpMethod: ann.method,
                fullPath,
                filePath,
                lineStart,
              },
              tags: ['endpoint', ann.method],
            });

            relationships.push({
              id: `rel-${controllerAssetId}-${endpointId}`,
              tenantId: context.tenantId,
              sourceAssetId: controllerAssetId,
              targetAssetId: endpointId,
              type: 'CONTAINS',
              nature: 'DECLARED',
              confidence: 1.0,
              evidenceRef: evidence.id,
              metadata: { httpMethod: ann.method },
            });
            break;
          }
        }
      }
    }

    return { assets, relationships, evidence: evidenceList };
  }
}
