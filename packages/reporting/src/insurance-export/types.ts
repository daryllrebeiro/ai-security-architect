export type EvidenceConfidenceLevel = 'DIRECT_EVIDENCE' | 'PARTIAL_EVIDENCE' | 'NOT_OBSERVABLE';

export interface UnderwritingQuestion {
  id: string;
  category: string;
  prompt: string;
  confidence: EvidenceConfidenceLevel;
  directEvidenceCount: number;
  partialEvidenceNotes: string[];
  findingsCorrelated: string[]; // Finding IDs
  underwriterAnswerDraft: string;
  sourceAssets: string[];
}

export const INSURANCE_DRAFT_DISCLAIMER =
  '(DRAFT ASSISTANT ONLY: This document provides technical evidence to assist human legal, compliance, and risk officers. It does not constitute an authoritative or legally binding final insurance submission.)';

export interface InsuranceReportSummary {
  tenantId: string;
  generatedAt: string;
  totalQuestionsEvaluated: number;
  directEvidenceQuestions: number;
  partialEvidenceQuestions: number;
  notObservableQuestions: number;
  questions: UnderwritingQuestion[];
  disclaimer: string;
}
