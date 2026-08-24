import type { Asset, Relationship, Evidence } from '@ai-security-architect/core';
import type { EphemeralWorkspace } from '@ai-security-architect/ingestion';

export interface DiscoveryContext {
  tenantId: string;
  repository: string;
  workspace: EphemeralWorkspace;
}

export interface DiscoveryResult {
  assets: Asset[];
  relationships: Relationship[];
  evidence: Evidence[];
}

export interface DiscoveryExtractor {
  readonly name: string;
  supports(workspace: EphemeralWorkspace, fileList: string[]): Promise<boolean>;
  extract(context: DiscoveryContext, fileList: string[]): Promise<DiscoveryResult>;
}
