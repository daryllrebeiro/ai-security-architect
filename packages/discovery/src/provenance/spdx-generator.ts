import { randomUUID } from 'node:crypto';
import type {
  DiscoveredDependency,
  SbomGenerationOptions,
  SpdxDocument,
  SpdxPackage,
} from './types.js';

export class SpdxGenerator {
  public static generate(
    dependencies: DiscoveredDependency[],
    options: SbomGenerationOptions
  ): SpdxDocument {
    const timestamp = options.timestamp ?? new Date().toISOString();
    const serviceName = options.serviceName;
    const documentNamespace = `https://spdx.org/spdxdocs/${serviceName}-${randomUUID()}`;

    const packages: SpdxPackage[] = dependencies.map((dep, index) => {
      const spdxId = `SPDXRef-Package-${index + 1}-${dep.name.replace(/[^a-zA-Z0-9.-]/g, '-')}`;
      const purl = dep.purl ?? `pkg:${dep.ecosystem}/${dep.name}@${dep.version}`;

      return {
        SPDXID: spdxId,
        name: dep.name,
        versionInfo: dep.version,
        downloadLocation: 'NOASSERTION',
        filesAnalyzed: false,
        licenseConcluded: dep.license ?? 'NOASSERTION',
        licenseDeclared: dep.license ?? 'NOASSERTION',
        externalRefs: [
          {
            referenceCategory: 'PACKAGE-MANAGER',
            referenceType: 'purl',
            referenceLocator: purl,
          },
        ],
      };
    });

    const relationships = packages.map((pkg) => ({
      spdxElementId: 'SPDXRef-DOCUMENT',
      relatedSpdxElement: pkg.SPDXID,
      relationshipType: 'DESCRIBES',
    }));

    return {
      spdxVersion: 'SPDX-2.3',
      dataLicense: 'CC0-1.0',
      SPDXID: 'SPDXRef-DOCUMENT',
      name: serviceName,
      documentNamespace,
      creationInfo: {
        created: timestamp,
        creators: ['Tool: ai-security-architect-spdx-1.0.0'],
      },
      packages,
      relationships,
    };
  }

  public static generateJson(
    dependencies: DiscoveredDependency[],
    options: SbomGenerationOptions
  ): string {
    return JSON.stringify(this.generate(dependencies, options), null, 2);
  }
}
