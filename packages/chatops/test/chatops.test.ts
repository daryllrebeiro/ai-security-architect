import { describe, it, expect } from 'vitest';
import * as crypto from 'node:crypto';
import { WormAuditLogger } from '@ai-security-architect/enterprise';
import { SecurityGraphEngine } from '@ai-security-architect/graph';
import { NLQueryPipeline } from '@ai-security-architect/nl-query';
import {
  ChatOpsService,
  ChatOpsPatchApprovalHandler,
  type ChatMessageEvent,
  type ChatActionEvent,
} from '../src/index.js';

describe('Task F.1 — ChatOps Bot (Slack/Teams Interactive Assistant)', () => {
  const tenantId = 'tenant-chatops-01';

  function setupTestEnvironment() {
    const graph = new SecurityGraphEngine(tenantId);
    graph.addAsset({
      id: 'asset-db-vault',
      tenantId,
      type: 'DATABASE',
      name: 'customer-db',
      environment: 'production',
      isPublic: false,
      isSensitiveData: true,
      criticality: 'CRITICAL',
      tags: ['pii'],
      metadata: {},
    });
    graph.addAsset({
      id: 'asset-alb-ingress',
      tenantId,
      type: 'LOAD_BALANCER',
      name: 'public-alb',
      environment: 'production',
      isPublic: true,
      isSensitiveData: false,
      criticality: 'HIGH',
      tags: ['public'],
      metadata: {},
    });
    graph.addRelationship({
      id: 'rel-alb-to-db',
      tenantId,
      sourceAssetId: 'asset-alb-ingress',
      targetAssetId: 'asset-db-vault',
      type: 'ROUTES_TO',
      nature: 'DECLARED',
      confidence: 1.0,
      metadata: {},
    });

    const pipeline = new NLQueryPipeline();
    const auditLogger = new WormAuditLogger();

    const config = {
      tenantId,
      platform: 'SLACK' as const,
      defaultChannelId: 'C123456_SEC_ALERTS',
      authorizedApprovers: ['alice@corp.com', 'U_ALICE_SEC_ADMIN'],
      signingSecret: 'test-slack-signing-secret-12345',
    };

    const approvalHandler = new ChatOpsPatchApprovalHandler(config, auditLogger);
    const service = new ChatOpsService(config, pipeline, graph, approvalHandler);

    return { graph, pipeline, auditLogger, service, config };
  }

  describe('Ad-hoc In-Channel NL Queries', () => {
    it('routes in-channel questions through NLQueryPipeline with grounding discipline', async () => {
      const { service } = setupTestEnvironment();

      const event: ChatMessageEvent = {
        platform: 'SLACK',
        channelId: 'C123456_SEC_ALERTS',
        userId: 'U_DEV_USER',
        text: 'What public attack paths reach the database?',
      };

      const response = await service.onMessage(event);
      expect(response.text).toBeDefined();
      expect(response.text).toContain('customer-db');
      expect(response.text).toContain('Grounded in graph evidence');
    });

    it('safely declines unsafe or out-of-scope in-channel queries', async () => {
      const { service } = setupTestEnvironment();

      const event: ChatMessageEvent = {
        platform: 'SLACK',
        channelId: 'C123456_SEC_ALERTS',
        userId: 'U_DEV_USER',
        text: 'What is the weather today?',
      };

      const response = await service.onMessage(event);
      expect(response.text).toContain('Query declined');
    });
  });

  describe('Interactive Remediation Patch Approval & RBAC', () => {
    it('approves patch when action is triggered by an authorized identity and writes WORM audit log', async () => {
      const { service, auditLogger } = setupTestEnvironment();

      const authorizedAction: ChatActionEvent = {
        platform: 'SLACK',
        actionId: 'approve_patch',
        patchId: 'patch-iam-least-privilege-001',
        userId: 'U_ALICE_SEC_ADMIN',
        userEmail: 'alice@corp.com',
        channelId: 'C123456_SEC_ALERTS',
      };

      const result = await service.onAction(authorizedAction);

      expect(result.status).toBe('APPROVED');
      expect(result.actingUserId).toBe('alice@corp.com');
      expect(result.message).toContain('approved');

      // Verify WORM audit log
      const entries = auditLogger.getAllEntries();
      const approvalEntry = entries.find((e) => e.action === 'AUDIT_REMEDIATION_APPROVED');
      expect(approvalEntry).toBeDefined();
      expect(approvalEntry?.resourceId).toBe('patch-iam-least-privilege-001');
      expect(approvalEntry?.userId).toBe('alice@corp.com');
    });

    it('rejects patch approval when action is triggered by an unauthorized identity and writes audit incident', async () => {
      const { service, auditLogger } = setupTestEnvironment();

      const unauthorizedAction: ChatActionEvent = {
        platform: 'SLACK',
        actionId: 'approve_patch',
        patchId: 'patch-iam-least-privilege-001',
        userId: 'U_MALLORY_INTERN',
        userEmail: 'mallory@corp.com', // NOT in authorizedApprovers
        channelId: 'C123456_SEC_ALERTS',
      };

      const result = await service.onAction(unauthorizedAction);

      expect(result.status).toBe('UNAUTHORIZED');
      expect(result.actingUserId).toBe('mallory@corp.com');
      expect(result.message).toContain('Unauthorized');

      // Verify WORM audit log records unauthorized rejection
      const entries = auditLogger.getAllEntries();
      const rejectedEntry = entries.find(
        (e) => e.action === 'AUDIT_REMEDIATION_APPROVAL_REJECTED_UNAUTHORIZED'
      );
      expect(rejectedEntry).toBeDefined();
      expect(rejectedEntry?.resourceId).toBe('patch-iam-least-privilege-001');
      expect(rejectedEntry?.userId).toBe('mallory@corp.com');
    });
  });

  describe('Cryptographic Signature Verification & Replay Protection', () => {
    it('validates authentic Slack HMAC signatures and rejects forged or expired payloads', () => {
      const { service, config } = setupTestEnvironment();

      const nowSeconds = Math.floor(Date.now() / 1000);
      const rawBody = JSON.stringify({ event: 'button_click', payload: '123' });

      // 1. Valid signature
      const validBasestring = `v0:${nowSeconds}:${rawBody}`;
      const validHmac = crypto
        .createHmac('sha256', config.signingSecret!)
        .update(validBasestring)
        .digest('hex');
      const validSigHeader = `v0=${validHmac}`;

      expect(service.verifySlackSignature(validSigHeader, String(nowSeconds), rawBody)).toBe(true);

      // 2. Tampered body
      const tamperedBody = JSON.stringify({ event: 'button_click', payload: 'TAMPERED' });
      expect(service.verifySlackSignature(validSigHeader, String(nowSeconds), tamperedBody)).toBe(false);

      // 3. Stale timestamp (10 minutes ago -> replay attack)
      const tenMinutesAgo = nowSeconds - 600;
      expect(service.verifySlackSignature(validSigHeader, String(tenMinutesAgo), rawBody)).toBe(false);
    });
  });
});
