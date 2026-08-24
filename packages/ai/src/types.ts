import type {
  AttackPath,
  AIContextHandoff,
  AIReasoningOutput,
} from '@ai-security-architect/core';
import type { SecurityGraphEngine } from '@ai-security-architect/graph';

export interface LLMProvider {
  readonly name: string;
  generateCompletion(prompt: string, systemPrompt: string): Promise<string>;
}

export interface AIReasoningRequest {
  attackPath: AttackPath;
  graph: SecurityGraphEngine;
  repository: string;
  llmProvider?: LLMProvider;
}

export interface AIReasoningResponse {
  output: AIReasoningOutput;
  contextHandoff: AIContextHandoff;
  executionTimeMs: number;
  provider: string;
}
