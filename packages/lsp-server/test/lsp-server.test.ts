import { describe, it, expect, afterEach, vi } from 'vitest';
import * as path from 'node:path';
import { DiagnosticSeverity } from 'vscode-languageserver';
import { TextDocument } from 'vscode-languageserver-textdocument';
import {
  WorkspaceManager,
  RepositoryAcquisitionManager,
  type EphemeralWorkspace,
} from '@ai-security-architect/ingestion';
import { DiagnosticEngine } from '../src/diagnostic-engine.js';
import { SecurityLspServer } from '../src/server.js';

describe('Real-Time IDE Security Architect (LSP Server)', () => {
  let createdWorkspaces: EphemeralWorkspace[] = [];

  afterEach(async () => {
    for (const ws of createdWorkspaces) {
      await ws.cleanup().catch(() => {});
    }
    createdWorkspaces = [];
  });

  async function setupFixtureWorkspace(): Promise<EphemeralWorkspace> {
    const manager = new WorkspaceManager();
    const workspace = await manager.createWorkspace();
    createdWorkspaces.push(workspace);

    const acquirer = new RepositoryAcquisitionManager();
    const fixturePath = path.resolve('fixtures/001-ssrf-iam-s3');
    await acquirer.acquire(
      {
        type: 'LOCAL_DIRECTORY',
        path: fixturePath,
      },
      workspace
    );

    return workspace;
  }

  it('DiagnosticEngine publishes real-time attack path diagnostics in sub-second SLA (<1000ms)', async () => {
    const workspace = await setupFixtureWorkspace();
    const engine = new DiagnosticEngine({
      tenantId: 'tenant-lsp-test',
      repository: 'enterprise/order-app',
      offlineMode: true,
    });

    const docUri = 'file:///workspace/terraform/iam.tf';
    const filePath = 'terraform/iam.tf';

    // 1. Initial analysis with active attack path
    const result = await engine.analyzeDocument(workspace, filePath, docUri);

    expect(result.durationMs).toBeLessThan(1000); // Sub-second SLA guarantee
    expect(result.diagnostics.length).toBeGreaterThan(0);

    const attackPathDiag = result.diagnostics.find(
      (d) => d.message.includes('Active Exploit Chain') || d.message.includes('Security Architect')
    );
    expect(attackPathDiag).toBeDefined();
    expect(attackPathDiag?.severity).toBe(DiagnosticSeverity.Error);
    expect(attackPathDiag?.source).toBe('ai-security-architect');
    expect(attackPathDiag?.message).toContain('crown jewel');
    expect(attackPathDiag?.message).toContain('Optimal Min-Cut Choke Point');

    // 2. Developer remediates IAM wildcard in editor
    const originalIam = await workspace.readSafeFile('terraform/iam.tf');
    const fixedIam = originalIam.replace('"s3:*"', '["s3:GetObject"]');
    await workspace.writeSafeFile('terraform/iam.tf', fixedIam);

    // 3. Re-analysis on save/change: Attack path should be completely severed!
    const reAnalysis = await engine.analyzeDocument(workspace, filePath, docUri);
    expect(reAnalysis.durationMs).toBeLessThan(1000);

    const remainingAttackPathDiags = reAnalysis.diagnostics.filter((d) =>
      d.message.includes('Active Exploit Chain')
    );
    expect(remainingAttackPathDiags.length).toBe(0); // Cleared in real-time!
  });

  it('SecurityLspServer dispatches diagnostics through language server protocol connection', async () => {
    const workspace = await setupFixtureWorkspace();

    const mockSendDiagnostics = vi.fn();
    const mockConnection: any = {
      onInitialize: vi.fn(),
      onDidSave: vi.fn(),
      onDidChangeContent: vi.fn(),
      onDidOpenTextDocument: vi.fn(),
      onDidChangeTextDocument: vi.fn(),
      onDidCloseTextDocument: vi.fn(),
      onDidSaveTextDocument: vi.fn(),
      onWillSaveTextDocument: vi.fn(),
      onWillSaveTextDocumentWaitUntil: vi.fn(),
      sendDiagnostics: mockSendDiagnostics,
      listen: vi.fn(),
    };

    const server = new SecurityLspServer({
      connection: mockConnection,
      workspace,
      config: { offlineMode: true },
    });

    const textDocument = TextDocument.create(
      'file:///workspace/terraform/iam.tf',
      'terraform',
      1,
      await workspace.readSafeFile('terraform/iam.tf')
    );

    await server.validateTextDocument(textDocument);

    expect(mockSendDiagnostics).toHaveBeenCalledTimes(1);
    const callArgs = mockSendDiagnostics.mock.calls[0][0];
    expect(callArgs.uri).toBe('file:///workspace/terraform/iam.tf');
    expect(callArgs.diagnostics.length).toBeGreaterThan(0);
    expect(callArgs.diagnostics[0].source).toBe('ai-security-architect');
  });
});
