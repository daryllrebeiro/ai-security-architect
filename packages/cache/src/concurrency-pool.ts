import * as os from 'node:os';

export interface ConcurrencyPoolOptions {
  maxConcurrency?: number;
}

export class ConcurrencyPool {
  private readonly maxConcurrency: number;

  constructor(options: ConcurrencyPoolOptions = {}) {
    this.maxConcurrency = options.maxConcurrency ?? Math.max(2, os.cpus().length || 4);
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
}
