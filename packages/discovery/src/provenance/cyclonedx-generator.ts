import { randomUUID } from 'node:crypto';
import type {
  CycloneDxBom,
  CycloneDxComponent,
  DiscoveredDependency,
  SbomGenerationOptions,
} from './types.js';

export class CycloneDxGenerator {
  public static generate(
    dependencies: DiscoveredDependency[],
    options: SbomGenerationOptions
  ): CycloneDxBom {
    const timestamp = options.timestamp ?? new Date().toISOString();
    const serviceName = options.serviceName;
    const version = options.version ?? '1.0.0';

    const components: CycloneDxComponent[] = dependencies.map((dep) => {
      const purl = dep.purl ?? `pkg:${dep.ecosystem}/${dep.name}@${dep.version}`;
      const bomRef = `pkg:${dep.ecosystem}/${dep.name}@${dep.version}`;

      const component: CycloneDxComponent = {
        'bom-ref': bomRef,
        type: 'library',
        name: dep.name,
        version: dep.version,
        purl,
        scope: dep.isDirect ? 'required' : 'optional',
      };

      if (dep.license) {
        component.licenses = [
          {
            license: {
              id: dep.license,
            },
          },
        ];
      }

      return component;
    });

    const dependencyGraph = dependencies.map((dep) => ({
      ref: `pkg:${dep.ecosystem}/${dep.name}@${dep.version}`,
      dependsOn: (dep.dependencies ?? []).map((child) => `pkg:${dep.ecosystem}/${child}`),
    }));

    return {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: `urn:uuid:${randomUUID()}`,
      version: 1,
      metadata: {
        timestamp,
        tools: [
          {
            vendor: 'ai-security-architect',
            name: 'CycloneDxGenerator',
            version: '1.0.0',
          },
        ],
        component: {
          type: 'application',
          name: serviceName,
          version,
        },
      },
      components,
      dependencies: dependencyGraph,
    };
  }

  public static generateJson(
    dependencies: DiscoveredDependency[],
    options: SbomGenerationOptions
  ): string {
    return JSON.stringify(this.generate(dependencies, options), null, 2);
  }
}
