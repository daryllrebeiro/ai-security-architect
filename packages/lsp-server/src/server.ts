import {
  createConnection,
  TextDocuments,
  ProposedFeatures,
  InitializeParams,
  InitializeResult,
  TextDocumentSyncKind,
  type Connection,
} from 'vscode-languageserver/node.js';
import { TextDocument } from 'vscode-languageserver-textdocument';
import type { EphemeralWorkspace } from '@ai-security-architect/ingestion';
import { DiagnosticEngine } from './diagnostic-engine.js';
import type { LspServerConfig } from './types.js';

export class SecurityLspServer {
  public readonly connection: Connection;
  public readonly documents: TextDocuments<TextDocument>;
  public readonly diagnosticEngine: DiagnosticEngine;
  private workspace?: EphemeralWorkspace;

  constructor(options: {
    connection?: Connection;
    diagnosticEngine?: DiagnosticEngine;
    config?: LspServerConfig;
    workspace?: EphemeralWorkspace;
  } = {}) {
    this.connection = options.connection ?? createConnection(ProposedFeatures.all);
    this.documents = new TextDocuments(TextDocument);
    this.diagnosticEngine = options.diagnosticEngine ?? new DiagnosticEngine(options.config);
    this.workspace = options.workspace;

    this.setupHandlers();
  }

  public setWorkspace(workspace: EphemeralWorkspace): void {
    this.workspace = workspace;
  }

  private setupHandlers(): void {
    this.connection.onInitialize((_params: InitializeParams): InitializeResult => {
      return {
        capabilities: {
          textDocumentSync: TextDocumentSyncKind.Incremental,
        },
      };
    });

    this.documents.onDidSave(async (event) => {
      await this.validateTextDocument(event.document);
    });

    this.documents.onDidChangeContent(async (event) => {
      await this.validateTextDocument(event.document);
    });

    this.documents.listen(this.connection);
  }

  public async validateTextDocument(textDocument: TextDocument): Promise<void> {
    if (!this.workspace) {
      return;
    }

    const uri = textDocument.uri;
    const filePath = uri.startsWith('file://') ? uri.replace(/^file:\/\/\/?/, '') : uri;

    try {
      const result = await this.diagnosticEngine.analyzeDocument(
        this.workspace,
        filePath,
        uri
      );

      this.connection.sendDiagnostics({
        uri: textDocument.uri,
        diagnostics: result.diagnostics,
      });
    } catch {
      // In offline/error scenarios, send empty diagnostics to avoid stale errors
      this.connection.sendDiagnostics({
        uri: textDocument.uri,
        diagnostics: [],
      });
    }
  }

  public listen(): void {
    this.connection.listen();
  }
}
