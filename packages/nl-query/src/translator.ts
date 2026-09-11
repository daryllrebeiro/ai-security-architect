import type { LLMProvider } from '@ai-security-architect/ai';
import { NLQueryDsl, NLQueryDslSchema } from './dsl.js';

const SYSTEM_PROMPT = `You are a specialized security query compiler for a Security Knowledge Graph.
Your job is to translate a user's natural language question into a structured JSON DSL query.
If the question is unrelated to the security graph, architecture topology, asset reachability, attack paths, or permissions, you MUST decline the request by providing "declinedReason".

The JSON schema must strictly conform to:
{
  "startNodeType"?: string,
  "startAssetId"?: string,
  "startAssetName"?: string,
  "direction": "FORWARD" | "REVERSE" | "ANY",
  "relationshipTypes"?: string[],
  "targetNodeType"?: string,
  "targetAssetId"?: string,
  "targetTagFilters"?: string[],
  "isSensitiveDataOnly"?: boolean,
  "isPublicOnly"?: boolean,
  "maxHops"?: number,
  "declinedReason"?: string
}

Respond ONLY with valid JSON. No conversational preamble or code markdown blocks.`;

export class NLQueryTranslator {
  constructor(private readonly llmProvider?: LLMProvider) {}

  public async translate(query: string): Promise<NLQueryDsl> {
    const trimmed = query.trim();

    // Check for obvious out-of-scope non-security questions
    if (this.isOutOfScope(trimmed)) {
      return {
        direction: 'FORWARD',
        maxHops: 5,
        declinedReason: 'The query is outside the scope of architectural security graph analysis.',
      };
    }

    if (this.llmProvider) {
      try {
        const rawResponse = await this.llmProvider.generateCompletion(trimmed, SYSTEM_PROMPT);
        const cleaned = rawResponse
          .replace(/```json/gi, '')
          .replace(/```/g, '')
          .trim();
        const parsed = JSON.parse(cleaned);
        const validated = NLQueryDslSchema.safeParse(parsed);
        if (validated.success) {
          return validated.data;
        }
      } catch {
        // Fallback to deterministic heuristic parsing if LLM output fails
      }
    }

    return this.heuristicTranslate(trimmed);
  }

  private isOutOfScope(query: string): boolean {
    const lower = query.toLowerCase();
    const outOfScopePatterns = [
      /\bweather\b/i,
      /\bpoem\b/i,
      /\brecipe\b/i,
      /\bjoke\b/i,
      /\bsong\b/i,
      /\bwho wrote\b/i,
      /\bcapital of\b/i,
      /\btranslate to french\b/i,
    ];
    return outOfScopePatterns.some((p) => p.test(lower));
  }

  private heuristicTranslate(query: string): NLQueryDsl {
    const lower = query.toLowerCase();

    const dsl: NLQueryDsl = {
      direction: 'FORWARD',
      maxHops: 5,
    };

    // Public / internet-facing check
    if (lower.includes('internet') || lower.includes('public') || lower.includes('external')) {
      dsl.isPublicOnly = true;
    }

    // Sensitive data / PII check
    if (lower.includes('pii') || lower.includes('sensitive') || lower.includes('customer data') || lower.includes('crown jewel')) {
      dsl.isSensitiveDataOnly = true;
      dsl.targetTagFilters = ['contains-pii'];
    }

    // Target types
    if (lower.includes('bucket') || lower.includes('s3')) {
      dsl.targetNodeType = 'BUCKET';
    } else if (lower.includes('database') || lower.includes('rds') || lower.includes('sql')) {
      dsl.targetNodeType = 'DATABASE';
    }

    // Start types
    if (lower.includes('service') || lower.includes('microservice')) {
      dsl.startNodeType = 'SERVICE';
    } else if (lower.includes('pod') || lower.includes('container')) {
      dsl.startNodeType = 'POD';
    } else if (lower.includes('load balancer') || lower.includes('alb')) {
      dsl.startNodeType = 'LOAD_BALANCER';
    }

    // Direction
    if (lower.includes('reach from') || lower.includes('reverse') || lower.includes('who can access')) {
      dsl.direction = 'REVERSE';
    }

    return dsl;
  }
}
