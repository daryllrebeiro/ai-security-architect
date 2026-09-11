import { describe, it, expect } from 'vitest';
import {
  ExtractorPluginRegistry,
  getDefaultExtractorRegistry,
  DiscoveryEngine,
  type DiscoveryExtractor,
  type DiscoveryContext,
  type DiscoveryResult,
} from '../src/index.js';
import type { EphemeralWorkspace } from '@ai-security-architect/ingestion';

describe('Milestone 2.3: Extractor Plugin Registry', () => {
  it('initializes with default core extractors', () => {
    const registry = new ExtractorPluginRegistry(true);
    expect(registry.hasExtractor('JavaSpringExtractor')).toBe(true);
    expect(registry.hasExtractor('KubernetesExtractor')).toBe(true);
    expect(registry.hasExtractor('TerraformExtractor')).toBe(true);
    expect(registry.hasExtractor('DockerExtractor')).toBe(true);
    expect(registry.hasExtractor('DependencyExtractor')).toBe(true);
    expect(registry.getExtractors().length).toBe(5);
  });

  it('registers and unregisters custom external extractors', () => {
    const registry = new ExtractorPluginRegistry(false);
    expect(registry.getExtractors()).toHaveLength(0);

    const mockPlugin: DiscoveryExtractor = {
      name: 'CustomCloudFormationExtractor',
      async supports(_ws: EphemeralWorkspace, fileList: string[]): Promise<boolean> {
        return fileList.some((f) => f.endsWith('.cf.yaml'));
      },
      async extract(_context: DiscoveryContext, _fileList: string[]): Promise<DiscoveryResult> {
        return { assets: [], relationships: [], evidence: [] };
      },
    };

    registry.registerExtractor(mockPlugin);
    expect(registry.hasExtractor('CustomCloudFormationExtractor')).toBe(true);
    expect(registry.getExtractor('CustomCloudFormationExtractor')).toBe(mockPlugin);
    expect(registry.getExtractors()).toHaveLength(1);

    const removed = registry.unregisterExtractor('CustomCloudFormationExtractor');
    expect(removed).toBe(true);
    expect(registry.hasExtractor('CustomCloudFormationExtractor')).toBe(false);
  });

  it('integrates seamlessly with DiscoveryEngine', () => {
    const registry = getDefaultExtractorRegistry();
    const engine = new DiscoveryEngine(registry.getExtractors());
    expect(engine).toBeDefined();
  });
});
