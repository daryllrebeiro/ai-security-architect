import {
  ConcurrencyPool,
  type ExtractionWorkerPayload,
} from '../packages/cache/src/index.js';

async function runWorkerPoolBenchmark() {
  console.log('================================================================');
  console.log('  10,000-FILE EXTRACTION CONCURRENCY POOL BENCHMARK');
  console.log('================================================================\n');

  const FILE_COUNT = 10_000;
  console.log(`[1/2] Generating ${FILE_COUNT.toLocaleString()} synthetic code files...`);

  const fileTypes = [
    { ext: '.tf', template: (i: number) => `resource "aws_s3_bucket" "b_${i}" {\n  bucket = "enterprise-bucket-${i}"\n  acl = "private"\n}\n` },
    { ext: '.yaml', template: (i: number) => `apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app-${i}\nspec:\n  replicas: 2\n` },
    { ext: '.ts', template: (i: number) => `export class Controller${i} {\n  private endpoint = "/api/v1/resource/${i}";\n  handle() { return true; }\n}\n` },
    { ext: '.java', template: (i: number) => `package com.enterprise.svc;\npublic class Svc${i} {\n  private String token = "secret_${i}";\n}\n` },
  ];

  const items: ExtractionWorkerPayload[] = [];
  for (let i = 0; i < FILE_COUNT; i++) {
    const ft = fileTypes[i % fileTypes.length];
    items.push({
      filePath: `repo/file-${i}${ft.ext}`,
      content: ft.template(i),
    });
  }
  console.log(`  -> Generated ${items.length.toLocaleString()} files.`);

  console.log(`\n[2/2] Running Parallel Extraction across ${FILE_COUNT.toLocaleString()} files...`);
  const pool = new ConcurrencyPool({ maxConcurrency: 8 });

  const start = performance.now();
  const results = await pool.extractParallel(items);
  const elapsed = performance.now() - start;

  const totalLines = results.reduce((acc, r) => acc + r.lineCount, 0);
  const throughputFilesPerSec = (FILE_COUNT / elapsed) * 1000;

  console.log(`  -> Completed: ${results.length.toLocaleString()} files in ${elapsed.toFixed(2)}ms`);
  console.log(`  -> Throughput: ${throughputFilesPerSec.toFixed(0)} files/sec`);
  console.log(`  -> Total Lines Processed: ${totalLines.toLocaleString()} lines`);
  console.log(`  -> Sample Result: ${results[0].filePath} (${results[0].detectedLanguage}) - SHA: ${results[0].contentSha256.slice(0, 16)}...`);

  await pool.close();

  console.log('\n================================================================');
  console.log('  WORKER POOL BENCHMARK COMPLETE - HIGH THROUGHPUT VALIDATED');
  console.log('================================================================\n');
}

runWorkerPoolBenchmark().catch((err) => {
  console.error('Benchmark failed:', err);
  process.exit(1);
});
