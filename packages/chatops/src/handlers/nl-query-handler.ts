import type { NLQueryPipeline } from '@ai-security-architect/nl-query';
import type { SecurityGraphEngine } from '@ai-security-architect/graph';
import type { ChatMessageEvent, ChatMessageResponse } from '../types.js';

export class ChatOpsNlQueryHandler {
  private pipeline: NLQueryPipeline;
  private graph: SecurityGraphEngine;

  constructor(pipeline: NLQueryPipeline, graph: SecurityGraphEngine) {
    this.pipeline = pipeline;
    this.graph = graph;
  }

  public async handleMessage(event: ChatMessageEvent): Promise<ChatMessageResponse> {
    const prompt = event.text.trim();
    if (!prompt) {
      return {
        text: 'Please provide a security query (e.g., "What attack paths reach the customer database?")',
        threadId: event.threadId,
      };
    }

    const result = await this.pipeline.query(prompt, this.graph);

    if (result.declined) {
      return {
        text: `⚠️ Query declined: ${result.declinedReason ?? 'The query cannot be safely translated into bounded graph queries.'}`,
        threadId: event.threadId,
      };
    }

    const groundingNote = result.totalPathsFound > 0
      ? `✅ Grounded in graph evidence (${result.totalPathsFound} path(s) verified)`
      : 'ℹ️ Grounded search: No matching paths in current graph topology.';

    const formattedText = [
      `*Query*: "${prompt}"`,
      '',
      result.groundedAnswer,
      '',
      `_${groundingNote}_`,
    ]
      .filter(Boolean)
      .join('\n');

    return {
      text: formattedText,
      threadId: event.threadId,
    };
  }
}
