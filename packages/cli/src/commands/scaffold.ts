import { PavedRoadRegistry } from '@ai-security-architect/paved-road';

export async function executeScaffold(options: {
  templateName: string;
}): Promise<void> {
  const registry = new PavedRoadRegistry();
  const tmpl = registry.getTemplate(options.templateName);
  if (!tmpl) {
    const available = registry.listTemplates().map((t) => t.name).join(', ');
    throw new Error(`Template "${options.templateName}" not found. Available: ${available}`);
  }

  const validation = registry.validateTemplate(tmpl);
  console.log(`\n=== Paved Road Scaffolding: ${tmpl.title} ===`);
  console.log(`Validation Status: ${validation.valid ? 'PASSED (0 Attack Paths)' : 'FAILED'}`);
  if (validation.formalProofVerified) {
    console.log(`Formal Proof: ${validation.formalProofStatus}`);
  }

  console.log('\nGenerated Scaffolding Files:');
  for (const [file, content] of Object.entries(tmpl.files)) {
    console.log(`\n--- [FILE: ${file}] ---`);
    console.log(content);
  }
}
