import * as readline from 'node:readline/promises';
import { NLQueryPipeline, type NLQueryResult } from '@ai-security-architect/nl-query';
import { executeScan } from './scan.js';
import type { CliQueryOptions } from '../types.js';

export async function executeQuery(options: CliQueryOptions & { repl?: boolean }): Promise<NLQueryResult> {
  const scanResult = await executeScan({
    path: options.path,
    tenantId: options.tenantId,
    silent: true,
  });

  const pipeline = new NLQueryPipeline();

  const runSingleQuery = async (queryText: string): Promise<NLQueryResult> => {
    const result = await pipeline.query(queryText, scanResult.graph);

    console.log(`\n================================================================================`);
    console.log(`  NATURAL LANGUAGE ARCHITECTURE QUERY`);
    console.log(`================================================================================`);
    console.log(`  Query:      "${result.query}"`);
    console.log(`  Intent:     ${result.dsl.direction} (Target: ${result.dsl.targetNodeType || 'ANY'})`);
    console.log(`  Matches:    ${result.totalPathsFound} attack paths`);
    console.log(`--------------------------------------------------------------------------------`);
    console.log(`  GROUNDED ANSWER:`);
    console.log(`  ${result.groundedAnswer}`);
    console.log(`--------------------------------------------------------------------------------`);

    if (result.matchedPaths.length > 0) {
      console.log(`  Exemplar Exploit Path:`);
      const p = result.matchedPaths[0];
      for (const step of p.steps) {
        console.log(`    -> (${step.relationshipType}) ${step.sourceAssetName} -> ${step.targetAssetName}`);
      }
    }
    console.log(`================================================================================\n`);
    return result;
  };

  const isRepl = options.repl || options.prompt === '--repl';

  if (isRepl) {
    console.log(`\nStarting Security Graph Interactive REPL (Type 'exit' or 'quit' to exit)...`);
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    let lastResult: NLQueryResult | null = null;
    try {
      while (true) {
        const question = await rl.question('sec-arch (query)> ');
        const trimmed = question.trim();
        if (!trimmed) continue;
        if (trimmed.toLowerCase() === 'exit' || trimmed.toLowerCase() === 'quit') {
          break;
        }
        lastResult = await runSingleQuery(trimmed);
      }
    } finally {
      rl.close();
    }

    return (
      lastResult ?? {
        query: 'exit',
        dsl: { direction: 'FORWARD', maxHops: 5 },
        declined: false,
        matchedPaths: [],
        groundedAnswer: 'REPL session ended.',
        totalPathsFound: 0,
      }
    );
  }

  return runSingleQuery(options.prompt);
}
