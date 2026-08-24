import {
  AIReasoningOutputSchema,
  type AIReasoningOutput,
} from '@ai-security-architect/core';
import type {
  LLMProvider,
  AIReasoningRequest,
  AIReasoningResponse,
} from './types.js';
import { ContextBuilder } from './context-builder.js';
import { PromptGenerator } from './prompt-generator.js';
import { RuleBasedLLMProvider } from './providers/rule-based-provider.js';

export class AIReasoningEngine {
  private readonly defaultProvider: LLMProvider;
  private readonly contextBuilder: ContextBuilder;
  private readonly promptGenerator: PromptGenerator;

  constructor(options: {
    defaultProvider?: LLMProvider;
    contextBuilder?: ContextBuilder;
    promptGenerator?: PromptGenerator;
  } = {}) {
    this.defaultProvider = options.defaultProvider ?? new RuleBasedLLMProvider();
    this.contextBuilder = options.contextBuilder ?? new ContextBuilder();
    this.promptGenerator = options.promptGenerator ?? new PromptGenerator();
  }

  public async reasonAboutAttackPath(
    request: AIReasoningRequest
  ): Promise<AIReasoningResponse> {
    const startTime = Date.now();
    const provider = request.llmProvider ?? this.defaultProvider;

    // 1. Build sanitized context handoff
    const contextHandoff = this.contextBuilder.buildContextHandoff(
      request.attackPath,
      request.graph,
      request.repository
    );

    // 2. Generate prompts
    const systemPrompt = this.promptGenerator.getSystemPrompt();
    const userPrompt = this.promptGenerator.getUserPrompt(contextHandoff);

    // 3. Invoke LLM Provider
    const rawResponse = await provider.generateCompletion(userPrompt, systemPrompt);

    // 4. Clean and parse JSON response
    let parsedJson: unknown;
    try {
      const cleaned = rawResponse
        .trim()
        .replace(/^```json\s*/i, '')
        .replace(/^```\s*/, '')
        .replace(/\s*```$/, '');
      parsedJson = JSON.parse(cleaned);
    } catch (err) {
      throw new Error(`AI returned invalid JSON response: ${(err as Error).message}\nRaw response:\n${rawResponse}`);
    }

    // 5. Strict Zod Schema Validation
    const output: AIReasoningOutput = AIReasoningOutputSchema.parse(parsedJson);

    // 6. Verify evidence citations match context handoff facts
    const validEvidenceIds = new Set(contextHandoff.evidenceReferences.map((e) => e.evidenceId));
    for (const citedId of output.evidenceReferences) {
      if (!validEvidenceIds.has(citedId)) {
        console.warn(`[AIReasoningEngine] AI cited unverified evidence ID: "${citedId}"`);
      }
    }

    return {
      output,
      contextHandoff,
      executionTimeMs: Date.now() - startTime,
      provider: provider.name,
    };
  }
}
