import * as crypto from 'node:crypto';
import type { NLQueryPipeline } from '@ai-security-architect/nl-query';
import type { SecurityGraphEngine } from '@ai-security-architect/graph';
import { ChatOpsNlQueryHandler } from './handlers/nl-query-handler.js';
import { ChatOpsSummaryPoster } from './handlers/summary-poster.js';
import { ChatOpsPatchApprovalHandler } from './handlers/patch-approval-handler.js';
import type {
  ChatActionEvent,
  ChatMessageEvent,
  ChatMessageResponse,
  ChatOpsConfig,
  ChatOpsScanSummaryPayload,
  PatchApprovalResult,
} from './types.js';

export class ChatOpsService {
  private config: ChatOpsConfig;
  private nlHandler: ChatOpsNlQueryHandler;
  private approvalHandler: ChatOpsPatchApprovalHandler;

  constructor(
    config: ChatOpsConfig,
    pipeline: NLQueryPipeline,
    graph: SecurityGraphEngine,
    approvalHandler?: ChatOpsPatchApprovalHandler
  ) {
    this.config = config;
    this.nlHandler = new ChatOpsNlQueryHandler(pipeline, graph);
    this.approvalHandler = approvalHandler ?? new ChatOpsPatchApprovalHandler(config);
  }

  public async onMessage(event: ChatMessageEvent): Promise<ChatMessageResponse> {
    return this.nlHandler.handleMessage(event);
  }

  public async onAction(event: ChatActionEvent): Promise<PatchApprovalResult> {
    return this.approvalHandler.handleAction(event);
  }

  public formatScanSummary(payload: ChatOpsScanSummaryPayload): ChatMessageResponse {
    return ChatOpsSummaryPoster.formatScanSummary(payload);
  }

  public verifySlackSignature(
    signatureHeader: string,
    timestampHeader: string,
    rawBody: string
  ): boolean {
    if (!this.config.signingSecret) {
      return true; // if no secret configured, pass in test mode
    }

    const fiveMinutesAgo = Math.floor(Date.now() / 1000) - 60 * 5;
    const reqTimestamp = parseInt(timestampHeader, 10);
    if (isNaN(reqTimestamp) || reqTimestamp < fiveMinutesAgo) {
      return false; // Replay attack protection
    }

    const sigBasestring = `v0:${timestampHeader}:${rawBody}`;
    const hmac = crypto
      .createHmac('sha256', this.config.signingSecret)
      .update(sigBasestring)
      .digest('hex');
    const mySignature = `v0=${hmac}`;

    try {
      return crypto.timingSafeEqual(
        Buffer.from(mySignature, 'utf8'),
        Buffer.from(signatureHeader, 'utf8')
      );
    } catch {
      return false;
    }
  }
}
