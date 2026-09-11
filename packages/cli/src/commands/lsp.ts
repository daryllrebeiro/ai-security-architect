import { SecurityLspServer } from '@ai-security-architect/lsp-server';

export async function executeLsp(): Promise<void> {
  console.log('Starting AI Security Architect Language Server (LSP)...');
  const server = new SecurityLspServer();
  server.listen();
}
