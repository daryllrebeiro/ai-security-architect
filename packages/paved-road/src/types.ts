import { SubgraphSpecification, CrownJewelInvariant } from '@ai-security-architect/attackpath';

export interface PavedRoadTemplate {
  name: string;
  title: string;
  category: 'API_SERVICE' | 'BACKGROUND_WORKER' | 'DATA_STORAGE';
  description: string;
  targetFormat: 'terraform' | 'kubernetes';
  files: Record<string, string>; // relativePath -> fileContent
  formalInvariant?: {
    invariant: CrownJewelInvariant;
    subgraph: SubgraphSpecification;
  };
}

export interface PavedRoadValidationResult {
  templateName: string;
  valid: boolean; // true if 0 critical/high attack paths
  detectedIssues: string[];
  formalProofVerified: boolean;
  formalProofStatus?: string;
}
