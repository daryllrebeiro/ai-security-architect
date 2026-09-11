import { WormAuditLogger, type SecurityContext } from '@ai-security-architect/enterprise';
import type { ChatActionEvent, ChatOpsConfig, PatchApprovalResult } from '../types.js';

export class ChatOpsPatchApprovalHandler {
  private auditLogger: WormAuditLogger;
  private config: ChatOpsConfig;

  constructor(config: ChatOpsConfig, auditLogger?: WormAuditLogger) {
    this.config = config;
    this.auditLogger = auditLogger ?? new WormAuditLogger();
  }

  public async handleAction(event: ChatActionEvent): Promise<PatchApprovalResult> {
    const timestamp = new Date().toISOString();
    const actingUser = event.userEmail ?? event.userId;

    const isAuthorized = this.config.authorizedApprovers.some(
      (auth) =>
        auth.toLowerCase() === event.userId.toLowerCase() ||
        (event.userEmail && auth.toLowerCase() === event.userEmail.toLowerCase())
    );

    const secCtx: SecurityContext = {
      tenantId: this.config.tenantId,
      userId: actingUser,
      userRole: isAuthorized ? 'SECURITY_ADMIN' : 'APP_ENGINEER',
      permissions: isAuthorized
        ? ['remediation:apply', 'remediation:propose', 'audit:read']
        : ['audit:read'],
      scopes: ['*'],
    };

    if (!isAuthorized) {
      // Log unauthorized attempt to WORM audit log
      this.auditLogger.log(
        secCtx,
        'AUDIT_REMEDIATION_APPROVAL_REJECTED_UNAUTHORIZED',
        event.patchId,
        {
          platform: event.platform,
          channelId: event.channelId,
          actingUserId: event.userId,
          actingUserEmail: event.userEmail,
          actionId: event.actionId,
          reason: 'User not in authorized approvers whitelist',
        }
      );

      return {
        patchId: event.patchId,
        status: 'UNAUTHORIZED',
        actingUserId: actingUser,
        timestamp,
        message: `⛔ Unauthorized: User '${actingUser}' does not possess permission to approve remediation patches. Incident audit logged.`,
      };
    }

    if (event.actionId === 'approve_patch') {
      // Log approval to WORM audit log
      this.auditLogger.log(secCtx, 'AUDIT_REMEDIATION_APPROVED', event.patchId, {
        platform: event.platform,
        channelId: event.channelId,
        actingUserId: event.userId,
        actingUserEmail: event.userEmail,
        authorized: true,
      });

      return {
        patchId: event.patchId,
        status: 'APPROVED',
        actingUserId: actingUser,
        timestamp,
        message: `✅ Patch '${event.patchId}' approved by '${actingUser}'. Applying remediation to target repository.`,
      };
    } else {
      // Log rejection to WORM audit log
      this.auditLogger.log(secCtx, 'AUDIT_REMEDIATION_REJECTED', event.patchId, {
        platform: event.platform,
        channelId: event.channelId,
        actingUserId: event.userId,
        actingUserEmail: event.userEmail,
      });

      return {
        patchId: event.patchId,
        status: 'REJECTED',
        actingUserId: actingUser,
        timestamp,
        message: `❌ Patch '${event.patchId}' was rejected by '${actingUser}'.`,
      };
    }
  }
}
