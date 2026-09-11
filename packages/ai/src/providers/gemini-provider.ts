import { GoogleGenAI } from '@google/genai';
import { zodToJsonSchema } from 'zod-to-json-schema';
import {
  AIReasoningOutputSchema,
  type AIReasoningOutput,
} from '@ai-security-architect/core';
import type { LLMProvider } from '../types.js';

export interface GeminiProviderOptions {
  apiKey?: string;
  primaryModel?: string;
  fallbackModel?: string;
  maxRetries?: number;
  client?: any; // For test injection
}

export class GeminiLLMProvider implements LLMProvider {
  public readonly name = 'GeminiLLMProvider';
  private readonly client: GoogleGenAI;
  private readonly primaryModel: string;
  private readonly fallbackModel: string;
  private readonly maxRetries: number;
  private readonly responseJsonSchema: Record<string, unknown>;

  constructor(options: GeminiProviderOptions = {}) {
    this.primaryModel = options.primaryModel || 'gemini-2.5-pro';
    this.fallbackModel = options.fallbackModel || 'gemini-3.6-flash';
    this.maxRetries = options.maxRetries ?? 2;

    const apiKey = options.apiKey || process.env.GEMINI_API_KEY || '';
    this.client = options.client || new GoogleGenAI({ apiKey });

    // Generate JSON Schema from canonical Zod schema
    const rawSchema = zodToJsonSchema(AIReasoningOutputSchema, {
      name: 'AIReasoningOutput',
      $refStrategy: 'none',
    }) as Record<string, unknown>;

    // Clean up $schema or definitions if present for Gemini API compatibility
    const { $schema, definitions, ...cleanSchema } = rawSchema;
    this.responseJsonSchema = cleanSchema;
  }

  public async generateCompletion(prompt: string, systemPrompt: string): Promise<string> {
    let currentPrompt = prompt;
    let currentSystemPrompt = systemPrompt;
    let lastError: Error | null = null;
    let attempts = 0;

    // Determine model based on prompt content (e.g. low-severity findings use flash)
    const isLowSeverity = prompt.includes('"severity": "LOW"') && !prompt.includes('"severity": "CRITICAL"');
    const selectedModel = isLowSeverity ? this.fallbackModel : this.primaryModel;

    while (attempts <= this.maxRetries) {
      attempts++;
      try {
        const response = await this.client.models.generateContent({
          model: selectedModel,
          contents: currentPrompt,
          config: {
            systemInstruction: currentSystemPrompt,
            responseMimeType: 'application/json',
            responseSchema: this.responseJsonSchema,
          },
        });

        const rawText = response.text || '';
        const cleaned = rawText
          .trim()
          .replace(/^```json\s*/i, '')
          .replace(/^```\s*/, '')
          .replace(/\s*```$/, '');

        const parsedJson = JSON.parse(cleaned);
        // Validate with Zod
        const validatedOutput = AIReasoningOutputSchema.parse(parsedJson);
        return JSON.stringify(validatedOutput, null, 2);
      } catch (err) {
        lastError = err as Error;

        if (attempts <= this.maxRetries) {
          // Construct Repair Prompt
          currentSystemPrompt = `${systemPrompt}\n\n[CRITICAL REPAIR INSTRUCTION] Your previous response failed schema validation with error: ${lastError.message}. You must strictly conform to the expected JSON schema and produce valid JSON with all required fields.`;
          currentPrompt = `${prompt}\n\nPlease fix the following validation error and re-generate the JSON response:\n${lastError.message}`;
        }
      }
    }

    // Fail-closed state: never fabricate invalid patches
    console.warn(`[GeminiLLMProvider] Failed after ${this.maxRetries + 1} attempts. Failing closed.`);
    const failClosedOutput: AIReasoningOutput = {
      summary: 'Automated AI reasoning failed schema verification.',
      rootCauseAnalysis: `AI reasoning could not complete successfully: ${lastError?.message || 'Schema validation error'}`,
      businessImpact: 'Unverified exploit path. Manual security analyst review required.',
      evidenceReferences: [],
      reasoningFailed: true,
      recommendedRemediation: {
        description: 'Manual intervention required. Automated patch generation failed closed.',
        targetChokePoint: 'manual-review-required',
        expectedRiskReductionPercentage: 0,
        engineeringEffort: 'HIGH',
        patches: [],
      },
      alternativeRemediations: [],
      confidence: 'MEDIUM',
    };

    return JSON.stringify(failClosedOutput, null, 2);
  }
}
