import type { DiscoveryExtractor } from './types.js';
import { JavaSpringExtractor } from './extractors/java-spring-extractor.js';
import { KubernetesExtractor } from './extractors/kubernetes-extractor.js';
import { TerraformExtractor } from './extractors/terraform-extractor.js';
import { DockerExtractor } from './extractors/docker-extractor.js';
import { DependencyExtractor } from './extractors/dependency-extractor.js';

export class ExtractorPluginRegistry {
  private readonly extractors = new Map<string, DiscoveryExtractor>();

  constructor(loadDefaults = true) {
    if (loadDefaults) {
      this.resetToDefaults();
    }
  }

  public registerExtractor(extractor: DiscoveryExtractor): void {
    if (!extractor.name) {
      throw new Error('Cannot register extractor without a valid name');
    }
    this.extractors.set(extractor.name, extractor);
  }

  public unregisterExtractor(name: string): boolean {
    return this.extractors.delete(name);
  }

  public getExtractor(name: string): DiscoveryExtractor | undefined {
    return this.extractors.get(name);
  }

  public hasExtractor(name: string): boolean {
    return this.extractors.has(name);
  }

  public getExtractors(): DiscoveryExtractor[] {
    return Array.from(this.extractors.values());
  }

  public clear(): void {
    this.extractors.clear();
  }

  public resetToDefaults(): void {
    this.extractors.clear();
    const defaults: DiscoveryExtractor[] = [
      new JavaSpringExtractor(),
      new KubernetesExtractor(),
      new TerraformExtractor(),
      new DockerExtractor(),
      new DependencyExtractor(),
    ];
    for (const ext of defaults) {
      this.registerExtractor(ext);
    }
  }
}

let defaultRegistryInstance: ExtractorPluginRegistry | null = null;

export function getDefaultExtractorRegistry(): ExtractorPluginRegistry {
  if (!defaultRegistryInstance) {
    defaultRegistryInstance = new ExtractorPluginRegistry(true);
  }
  return defaultRegistryInstance;
}
