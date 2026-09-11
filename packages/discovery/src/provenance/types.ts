import { z } from 'zod';
import type { Asset, Relationship, Finding, Evidence } from '@ai-security-architect/core';

export const SbomFormatSchema = z.enum(['CycloneDX', 'SPDX']);
export type SbomFormat = z.infer<typeof SbomFormatSchema>;

export interface DiscoveredDependency {
  name: string;
  version: string;
  ecosystem: 'npm' | 'maven' | 'pypi' | 'golang' | 'cargo';
  license?: string;
  purl?: string;
  isDirect?: boolean;
  dependencies?: string[];
}

export interface SbomGenerationOptions {
  serviceName: string;
  version?: string;
  tenantId?: string;
  author?: string;
  timestamp?: string;
}

export interface CycloneDxComponent {
  'bom-ref': string;
  type: 'library' | 'application' | 'framework' | 'container';
  name: string;
  version: string;
  purl?: string;
  scope?: 'required' | 'optional' | 'excluded';
  licenses?: Array<{
    license: {
      id?: string;
      name?: string;
    };
  }>;
}

export interface CycloneDxBom {
  bomFormat: 'CycloneDX';
  specVersion: '1.5';
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools?: Array<{ vendor?: string; name: string; version?: string }>;
    component: {
      type: 'application';
      name: string;
      version: string;
    };
  };
  components: CycloneDxComponent[];
  dependencies?: Array<{
    ref: string;
    dependsOn: string[];
  }>;
}

export interface SpdxPackage {
  SPDXID: string;
  name: string;
  versionInfo: string;
  downloadLocation: string;
  filesAnalyzed: boolean;
  licenseConcluded: string;
  licenseDeclared: string;
  externalRefs?: Array<{
    referenceCategory: 'PACKAGE-MANAGER' | 'SECURITY';
    referenceType: 'purl' | 'cpe23Type';
    referenceLocator: string;
  }>;
}

export interface SpdxDocument {
  spdxVersion: 'SPDX-2.3';
  dataLicense: 'CC0-1.0';
  SPDXID: 'SPDXRef-DOCUMENT';
  name: string;
  documentNamespace: string;
  creationInfo: {
    created: string;
    creators: string[];
  };
  packages: SpdxPackage[];
  relationships: Array<{
    spdxElementId: string;
    relatedSpdxElement: string;
    relationshipType: string;
  }>;
}

export interface ContainerProvenanceConfig {
  trustedRegistries?: string[];
  requireAttestation?: boolean;
  requireSignature?: boolean;
  targetEnvironment?: 'production' | 'staging' | 'development';
}

export interface ParsedDockerfileLineage {
  serviceId: string;
  serviceName: string;
  dockerfilePath: string;
  baseImage: string;
  tag?: string;
  digest?: string;
  registry?: string;
  isDigestPinned: boolean;
  isFloatingTag: boolean;
  hasSlsaProvenance: boolean;
  isCosignSigned: boolean;
}

export interface ContainerProvenanceResult {
  assets: Asset[];
  relationships: Relationship[];
  findings: Finding[];
  evidence: Evidence[];
}
