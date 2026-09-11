import type { LLMProvider } from '@ai-security-architect/ai';
import type { SecurityGraphEngine } from '@ai-security-architect/graph';
import { NLQueryTranslator } from './translator.js';
import { GraphQueryExecutor } from './graph-query-executor.js';
import { AnswerGrounder } from './answer-grounder.js';
import type { NLQueryResult, NLQueryDsl } from './dsl.js';

export class NLQueryPipeline {
  private readonly translator: NLQueryTranslator;
  private readonly executor: GraphQueryExecutor;
  private readonly grounder: AnswerGrounder;

  constructor(llmProvider?: LLMProvider) {
    this.translator = new NLQueryTranslator(llmProvider);
    this.executor = new GraphQueryExecutor();
    this.grounder = new AnswerGrounder(llmProvider);
  }

  public async query(naturalLanguagePrompt: string, graph: SecurityGraphEngine): Promise<NLQueryResult> {
    // Stage 1: Translate prompt into DSL
    const dsl: NLQueryDsl = await this.translator.translate(naturalLanguagePrompt);

    if (dsl.declinedReason) {
      return await this.grounder.groundAnswer(naturalLanguagePrompt, dsl, [], graph);
    }

    // Stage 2: Graph execution
    const matchedPaths = this.executor.execute(dsl, graph);

    // Stage 3: Answer formulation & grounding validation
    return await this.grounder.groundAnswer(naturalLanguagePrompt, dsl, matchedPaths, graph);
  }
}
