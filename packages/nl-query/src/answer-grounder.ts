import type { LLMProvider } from '@ai-security-architect/ai';
import type { SecurityGraphEngine } from '@ai-security-architect/graph';
import type { NLQueryDsl, GroundedPathResult, NLQueryResult } from './dsl.js';

export class AnswerGrounder {
  constructor(private readonly llmProvider?: LLMProvider) {}

  public async groundAnswer(
    query: string,
    dsl: NLQueryDsl,
    paths: GroundedPathResult[],
    graph: SecurityGraphEngine
  ): Promise<NLQueryResult> {
    if (dsl.declinedReason) {
      return {
        query,
        dsl,
        declined: true,
        declinedReason: dsl.declinedReason,
        matchedPaths: [],
        groundedAnswer: `Request Declined: ${dsl.declinedReason}`,
        totalPathsFound: 0,
      };
    }

    if (paths.length === 0) {
      return {
        query,
        dsl,
        declined: false,
        matchedPaths: [],
        groundedAnswer: `No architectural attack paths or access routes matching the criteria were found in the security graph.`,
        totalPathsFound: 0,
      };
    }

    // Verify grounding: Every cited node ID must exist in graph
    for (const path of paths) {
      for (const nodeId of path.nodeIds) {
        if (!graph.hasNode(nodeId)) {
          throw new Error(`Strict Grounding Violation: Node ID ${nodeId} cited in path does not exist in graph.`);
        }
      }
    }

    // Build structured deterministic baseline response
    const lines: string[] = [
      `### Security Graph Query Results`,
      `**Query:** "${query}"`,
      `**Paths Found:** ${paths.length}`,
      ``,
    ];

    paths.forEach((p, idx) => {
      lines.push(`#### Path ${idx + 1} (${p.pathLength} hops)`);
      lines.push(`- **Entrypoint:** \`${p.steps[0].sourceAssetName}\` (ID: \`${p.steps[0].sourceAssetId}\`, Type: \`${p.steps[0].sourceAssetType}\`)`);
      lines.push(`- **Target:** \`${p.steps[p.steps.length - 1].targetAssetName}\` (ID: \`${p.steps[p.steps.length - 1].targetAssetId}\`, Type: \`${p.steps[p.steps.length - 1].targetAssetType}\`)`);
      lines.push(``);
      lines.push(`**Step-by-step traversal:**`);
      p.steps.forEach((step, stepIdx) => {
        lines.push(
          `  ${stepIdx + 1}. \`${step.sourceAssetName}\` [\`${step.sourceAssetId}\`] ` +
          `--(${step.relationshipType} | edge: \`${step.relationshipId}\`)--> ` +
          `\`${step.targetAssetName}\` [\`${step.targetAssetId}\`]`
        );
      });
      lines.push(``);
    });

    let finalAnswer = lines.join('\n');

    // Stage 2 LLM grounding if LLM provider is configured
    if (this.llmProvider) {
      try {
        const systemPrompt = `You are a security architect grounder. Summarize the concrete query execution results in natural language.
You MUST explicitly reference the specific node IDs (e.g. [asset-id]) and relationship edge IDs from the result set.
You are strictly forbidden from mentioning any assets, paths, or vulnerabilities not present in the supplied results.`;

        const userPrompt = `User Question: "${query}"\nExecuted Traversal Results:\n${finalAnswer}\n\nPlease summarize the answer, citing specific node and edge IDs:`;
        const llmSummary = await this.llmProvider.generateCompletion(userPrompt, systemPrompt);
        if (llmSummary && llmSummary.trim().length > 0) {
          finalAnswer = `${llmSummary.trim()}\n\n---\n${finalAnswer}`;
        }
      } catch {
        // Fall back to deterministic grounded response
      }
    }

    return {
      query,
      dsl,
      declined: false,
      matchedPaths: paths,
      groundedAnswer: finalAnswer,
      totalPathsFound: paths.length,
    };
  }
}
