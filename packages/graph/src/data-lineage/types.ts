import type { Asset, Relationship } from '@ai-security-architect/core';

export interface DataBindingSpec {
  sourceAssetId: string;
  targetAssetId: string;
  dataType?: string; // e.g. 'PII', 'PAYMENT', 'CREDENTIALS', 'TELEMETRY'
  bindingTopicOrChannel?: string; // e.g. 'topic:user-signups'
  evidenceSnippet?: string;
  operation?: 'READ' | 'WRITE' | 'PUBLISH' | 'SUBSCRIBE' | 'LOG';
}

export interface DataLineageNode {
  asset: Asset;
  inheritedClassifications: string[];
  distanceFromSource: number;
  originatingSources: string[];
}

export interface DataLineagePath {
  nodes: Asset[];
  relationships: Relationship[];
  classifications: string[];
  hopsCount: number;
}

export interface ForwardTraceResult {
  sourceAsset: Asset;
  downstreamAssets: DataLineageNode[];
  allPaths: DataLineagePath[];
  propagatedClassifications: string[];
}

export interface ReverseTraceResult {
  targetAsset: Asset;
  upstreamSources: DataLineageNode[];
  allPaths: DataLineagePath[];
  handledClassifications: string[];
}
