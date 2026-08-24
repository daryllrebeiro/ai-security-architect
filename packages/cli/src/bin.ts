#!/usr/bin/env node
import { executeScan } from './commands/scan.js';
import { executeRemediate } from './commands/remediate.js';

async function main() {
  const args = process.argv.slice(2);
  const command = args[0] || 'help';

  if (command === 'scan') {
    const targetPath = args[1] || '.';
    const formatArg = args.find((a) => a.startsWith('--format='));
    const format = (formatArg ? formatArg.split('=')[1] : 'table') as 'table' | 'json' | 'sarif';

    const tenantArg = args.find((a) => a.startsWith('--tenant='));
    const tenantId = tenantArg ? tenantArg.split('=')[1] : 'tenant-default';

    await executeScan({
      path: targetPath,
      format,
      tenantId,
    });
  } else if (command === 'remediate') {
    const targetPath = args[1] || '.';
    const pathIdArg = args.find((a) => a.startsWith('--path='));
    const pathId = pathIdArg ? pathIdArg.split('=')[1] : 'path-001';

    await executeRemediate({
      path: targetPath,
      pathId,
    });
  } else {
    console.log(`
AI Security Architect CLI (sec-arch) v1.0.0

USAGE:
  sec-arch <command> [options]

COMMANDS:
  scan <path>              Scan repository, build security graph, and traverse attack paths
                           Options:
                             --format=[table|json|sarif]   Output format (default: table)
                             --tenant=<id>                 Tenant identifier

  remediate <path>         Synthesize AI remediation patch with closed-loop verification
                           Options:
                             --path=<pathId>               Target attack path ID (default: path-001)

  help                     Show this help message
`);
  }
}

main().catch((err) => {
  console.error('\n[Error]', err.message);
  process.exit(1);
});
