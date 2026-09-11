import * as os from 'node:os';
import * as fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import PiscinaPkg from 'piscina';
import {
  extractFileData,
  type ExtractionWorkerPayload,
  type ExtractionWorkerResult,
} from './workers/extraction-worker.js';

const PiscinaConstructor: any = (PiscinaPkg as any).default || PiscinaPkg;

export interface ConcurrencyPoolOptions {
  maxConcurrency?: number;
  useWorkerThreads?: boolean;
  workerScriptPath?: string;
}

export class ConcurrencyPool {
  private readonly maxConcurrency: number;
  private readonly useWorkerThreads: boolean;
  private piscina: any = null;
  private readonly workerScriptPath?: string;

  constructor(options: ConcurrencyPoolOptions = {}) {
    this.maxConcurrency = options.maxConcurrency ?? Math.max(2, os.cpus().length || 4);
    this.useWorkerThreads = options.useWorkerThreads ?? true;
    this.workerScriptPath = options.workerScriptPath;

    if (this.useWorkerThreads) {
      try {
        const candidateJs = fileURLToPath(new URL('./workers/extraction-worker.js', import.meta.url));
        const distJs = fileURLToPath(new URL('../dist/workers/extraction-worker.js', import.meta.url));

        let resolvedPath = this.workerScriptPath;
        if (!resolvedPath) {
          if (fs.existsSync(candidateJs)) {
            resolvedPath = candidateJs;
          } else if (fs.existsSync(distJs)) {
            resolvedPath = distJs;
          }
        }

        if (resolvedPath && fs.existsSync(resolvedPath)) {
          this.piscina = new PiscinaConstructor({
            filename: resolvedPath,
            maxThreads: this.maxConcurrency,
            minThreads: 1,
          });
        }
      } catch {
        this.piscina = null;
      }
    }
  }

  public isUsingWorkerThreads(): boolean {
    return this.piscina !== null;
  }

  public async map<T, R>(
    items: T[],
    fn: (item: T, index: number) => Promise<R>
  ): Promise<R[]> {
    if (items.length === 0) return [];

    const results: R[] = new Array(items.length);
    let nextIndex = 0;

    const workers = new Array(Math.min(this.maxConcurrency, items.length))
      .fill(null)
      .map(async () => {
        while (nextIndex < items.length) {
          const currentIndex = nextIndex++;
          results[currentIndex] = await fn(items[currentIndex], currentIndex);
        }
      });

    await Promise.all(workers);
    return results;
  }

  public async extractParallel(
    items: ExtractionWorkerPayload[]
  ): Promise<ExtractionWorkerResult[]> {
    if (items.length === 0) return [];

    if (this.piscina) {
      try {
        return await Promise.all(
          items.map((item) => this.piscina!.run(item) as Promise<ExtractionWorkerResult>)
        );
      } catch {
        return items.map((item) => extractFileData(item));
      }
    }

    return this.map(items, async (item) => extractFileData(item));
  }

  public async close(): Promise<void> {
    if (this.piscina) {
      await this.piscina.destroy();
      this.piscina = null;
    }
  }
}
