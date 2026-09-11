import { LiveValidator, DeclaredGraphExpectation } from '@ai-security-architect/live-validation';

export async function executeLiveValidate(options: {
  endpoints?: string[];
}): Promise<void> {
  const allowed = options.endpoints || ['https://api.internal.example.com/health'];
  const validator = new LiveValidator({
    enabled: true,
    allowedEndpoints: allowed,
  });

  console.log('\n=== Continuous Live Validation (Security Chaos Engineering) ===');
  console.log(`Auditing ${allowed.length} allowlisted endpoint(s)...`);

  const expectations: DeclaredGraphExpectation[] = allowed.map((ep, idx) => ({
    assetId: `asset-ep-${idx}`,
    tenantId: 'tenant-default',
    endpointUrl: ep,
    declaredReachable: true,
    declaredRequiresAuth: false,
  }));

  const probeResults = [];
  for (const ep of allowed) {
    const res = await validator.probeEndpoint(ep);
    probeResults.push(res);
    console.log(`- Probe [${res.reachable ? 'ONLINE' : 'UNREACHABLE'}] ${ep} (${res.latencyMs}ms)`);
  }

  const findings = validator.reconcile(expectations, probeResults);
  console.log(`Model Disagreements Identified: ${findings.length}`);
}
