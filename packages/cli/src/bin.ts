#!/usr/bin/env node
import { executeScan } from './commands/scan.js';
import { executeRemediate } from './commands/remediate.js';
import { executeAgent } from './commands/agent.js';
import { executeLsp } from './commands/lsp.js';
import { executeCompliance } from './commands/compliance.js';
import { executeFair } from './commands/fair.js';
import { executeRunbook } from './commands/runbook.js';
import { executeQuery } from './commands/query.js';
import { executeSimulate } from './commands/simulate.js';
import { executePolicy } from './commands/policy.js';
import { executeDashboard } from './commands/dashboard.js';
import { executeDiff } from './commands/diff.js';
import { executeFederate } from './commands/federate.js';

async function main() {
  const args = process.argv.slice(2);
  const command = args[0] || 'help';

  if (command === 'scan') {
    const targetPath = args[1] || '.';
    const formatArg = args.find((a) => a.startsWith('--format='));
    const format = (formatArg ? formatArg.split('=')[1] : 'table') as 'table' | 'json' | 'sarif';

    const tenantArg = args.find((a) => a.startsWith('--tenant='));
    const tenantId = tenantArg ? tenantArg.split('=')[1] : 'tenant-default';

    const withCloud = args.includes('--with-cloud');
    const regionArg = args.find((a) => a.startsWith('--region='));
    const region = regionArg ? regionArg.split('=')[1] : undefined;

    await executeScan({
      path: targetPath,
      format,
      tenantId,
      withCloud,
      region,
    });
  } else if (command === 'remediate') {
    const targetPath = args[1] || '.';
    const pathIdArg = args.find((a) => a.startsWith('--path='));
    const pathId = pathIdArg ? pathIdArg.split('=')[1] : 'path-001';

    await executeRemediate({
      path: targetPath,
      pathId,
    });
  } else if (command === 'agent') {
    const targetPath = args[1] || '.';
    const pathIdArg = args.find((a) => a.startsWith('--path='));
    const pathId = pathIdArg ? pathIdArg.split('=')[1] : undefined;
    const autoApprove = args.includes('--yes') || args.includes('-y');

    const maxIterArg = args.find((a) => a.startsWith('--max-iterations='));
    const maxIterations = maxIterArg ? parseInt(maxIterArg.split('=')[1], 10) : 5;

    await executeAgent({
      path: targetPath,
      pathId,
      autoApprove,
      maxIterations,
    });
  } else if (command === 'lsp') {
    await executeLsp();
  } else if (command === 'compliance') {
    const targetPath = args[1] || '.';
    const fwArg = args.find((a) => a.startsWith('--framework='));
    const frameworks = fwArg ? fwArg.split('=')[1].split(',') : undefined;

    const formatArg = args.find((a) => a.startsWith('--format='));
    const format = (formatArg ? formatArg.split('=')[1] : 'markdown') as 'markdown' | 'json';

    const outArg = args.find((a) => a.startsWith('--out='));
    const outputFile = outArg ? outArg.split('=')[1] : undefined;

    await executeCompliance({
      path: targetPath,
      frameworks,
      format,
      outputFile,
    });
  } else if (command === 'fair' || command === 'risk-quant') {
    const targetPath = args[1] || '.';
    const formatArg = args.find((a) => a.startsWith('--format='));
    const format = (formatArg ? formatArg.split('=')[1] : 'table') as 'table' | 'json';

    const currArg = args.find((a) => a.startsWith('--currency='));
    const currency = currArg ? currArg.split('=')[1] : 'USD';

    const outArg = args.find((a) => a.startsWith('--out='));
    const outputFile = outArg ? outArg.split('=')[1] : undefined;

    await executeFair({
      path: targetPath,
      format,
      currency,
      outputFile,
    });
  } else if (command === 'runbook') {
    const targetPath = args[1] || '.';
    const pathIdArg = args.find((a) => a.startsWith('--path='));
    const pathId = pathIdArg ? pathIdArg.split('=')[1] : undefined;

    const outArg = args.find((a) => a.startsWith('--out='));
    const outputFile = outArg ? outArg.split('=')[1] : undefined;

    await executeRunbook({
      path: targetPath,
      pathId,
      outputFile,
    });
  } else if (command === 'query') {
    const targetPath = args[1] || '.';
    const repl = args.includes('--repl');
    const promptArg = args.find((a) => !a.startsWith('--') && a !== 'query' && a !== targetPath);
    const prompt = promptArg || 'Which assets are exposed to the public internet?';

    await executeQuery({
      path: targetPath,
      prompt,
      repl,
    });
  } else if (command === 'simulate') {
    const targetPath = args[1] || '.';
    const entryArg = args.find((a) => a.startsWith('--entry='));
    const assumedBreachNode = entryArg ? entryArg.split('=')[1] : undefined;

    await executeSimulate({
      path: targetPath,
      assumedBreachNode,
    });
  } else if (command === 'policy') {
    const targetPath = args[1] || '.';
    const failOnBreach = args.includes('--fail') || args.includes('--enforce');

    await executePolicy({
      path: targetPath,
      failOnBreach,
    });
  } else if (command === 'dashboard') {
    const targetPath = args[1] || '.';
    const outArg = args.find((a) => a.startsWith('--out='));
    const outputFile = outArg ? outArg.split('=')[1] : undefined;
    const serve = args.includes('--serve');
    const portArg = args.find((a) => a.startsWith('--port='));
    const port = portArg ? parseInt(portArg.split('=')[1], 10) : undefined;

    await executeDashboard({
      path: targetPath,
      outputFile,
      serve,
      port,
    });
  } else if (command === 'diff') {
    const basePath = args[1] || 'main';
    const headPath = args[2] || '.';
    const formatArg = args.find((a) => a.startsWith('--format='));
    const format = (formatArg ? formatArg.split('=')[1] : 'table') as 'table' | 'markdown' | 'json';
    const prComment = args.includes('--pr-comment');
    const outArg = args.find((a) => a.startsWith('--out='));
    const outputFile = outArg ? outArg.split('=')[1] : undefined;

    await executeDiff({
      basePath,
      headPath,
      format,
      prComment,
      outputFile,
    });
  } else if (command === 'federate') {
    const manifestPath = args[1] || 'federation.json';
    const outArg = args.find((a) => a.startsWith('--out='));
    const outputFile = outArg ? outArg.split('=')[1] : undefined;
    const sqliteArg = args.find((a) => a.startsWith('--sqlite='));
    const sqlitePath = sqliteArg ? sqliteArg.split('=')[1] : undefined;

    await executeFederate({
      manifestPath,
      outputFile,
      sqlitePath,
    });
  } else {
    console.log(`
AI Security Architect CLI (sec-arch) v1.0.0

USAGE:
  sec-arch <command> [path] [options]

CORE COMMANDS:
  scan <path>              Scan repository, build security graph, and traverse attack paths
                           Options:
                             --format=[table|json|sarif]   Output format (default: table)
                             --tenant=<id>                 Tenant identifier
                             --with-cloud                  Correlate live AWS cloud runtime state & drift
                             --region=<region>             AWS region (default: us-east-1)

  remediate <path>         Synthesize AI remediation patch with closed-loop verification
                           Options:
                             --path=<pathId>               Target attack path ID (default: path-001)

  agent <path>             Autonomous multi-model iterative remediation agent with human approval gate
                           Options:
                             --path=<pathId>               Target attack path ID (default: highest risk)
                             --yes, -y                     Auto-approve verified pull request
                             --max-iterations=<n>          Maximum reasoning iterations (default: 5)

  lsp                      Launch Language Server Protocol (LSP) server for real-time IDE diagnostics

ENTERPRISE GOVERNANCE & COMPLIANCE:
  compliance <path>        Evaluate attack paths against regulatory frameworks (SOC2, PCI-DSS, ISO27001, HIPAA, NIST)
                           Options:
                             --framework=<list>            Comma-separated frameworks (e.g. SOC2,PCI-DSS)
                             --format=[markdown|json]      Output format (default: markdown)
                             --out=<file>                  Write report to file

  fair <path>              Quantify financial risk exposure using FAIR-aligned model (Annualized Loss Expectancy)
                           Options:
                             --format=[table|json]         Output format (default: table)
                             --currency=<code >            Currency code (default: USD)
                             --out=<file>                  Save financial exposure report

  runbook <path>           Generate step-by-step incident response and remediation runbook
                           Options:
                             --path=<pathId>               Target attack path (default: highest risk)
                             --out=<file>                  Save runbook markdown to file

  query <path> "<prompt>"  Ask natural language questions about the security graph topology
                           Example:
                             sec-arch query . "Which S3 buckets are reachable from the internet?"

  simulate <path>          Simulate hypothetical breaches and threat actor lateral movement (Purple Team Mode)
                           Options:
                             --entry=<assetId>             Assumed breached asset ID

  policy <path>            Enforce Policy-as-Code security budgets on repository architecture
                           Options:
                             --fail, --enforce             Exit with non-zero code on budget breach

  dashboard <path>         Generate historical risk trend burndown and MTTR tracking HTML dashboard
                           Options:
                             --out=<file>                  Output HTML dashboard file path
                             --serve                       Start local live HTTP dashboard server
                             --port=<n>                    Local dashboard server port (default: 3000)

  diff <base> <head>       Compute attack path delta between Git references, branches, or PRs
                           Options:
                             --format=[table|markdown|json] Output format (default: table)
                             --pr-comment                  Format output as GitHub/GitLab PR comment
                             --out=<file>                  Write diff report to file

  federate <manifest.json> Merge multi-repo graphs into an organization-wide enterprise security graph
                           Options:
                             --out=<file>                  Save merged federated graph JSON
                             --sqlite=<file>               Export to SQLite graph database

  help                     Show this help message
`);
  }
}

main().catch((err) => {
  console.error('\n[Error]', err.message);
  process.exit(1);
});
