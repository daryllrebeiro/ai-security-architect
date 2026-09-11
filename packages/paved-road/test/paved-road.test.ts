import { describe, it, expect } from 'vitest';
import {
  PavedRoadRegistry,
  PavedRoadTemplate,
} from '../src/index.js';

describe('Task I.4: Secure Reference Architecture / "Paved Road" Template Generator', () => {
  const registry = new PavedRoadRegistry();

  it('validates that every shipped template in the library passes zero-attack-path CI validation', () => {
    const templates = registry.listTemplates();
    expect(templates.length).toBeGreaterThanOrEqual(3);

    for (const tmpl of templates) {
      const res = registry.validateTemplate(tmpl);
      expect(res.valid).toBe(true);
      expect(res.detectedIssues.length).toBe(0);
    }
  });

  it('verifies that secure-db-access carries formally proven invariants (via Task G.2)', () => {
    const dbTmpl = registry.getTemplate('secure-db-access')!;
    expect(dbTmpl).toBeDefined();

    const res = registry.validateTemplate(dbTmpl);
    expect(res.valid).toBe(true);
    expect(res.formalProofVerified).toBe(true);
    expect(res.formalProofStatus).toContain('Formally Proven UNSAT');
  });

  it('fails CI validation when a deliberate regression is introduced into a template', () => {
    // Deliberate regression: Injecting publicly_accessible = true and open 0.0.0.0/0 on postgres port 5432
    const regressedTemplate: PavedRoadTemplate = {
      name: 'regressed-insecure-db',
      title: 'Flawed DB Architecture',
      category: 'DATA_STORAGE',
      description: 'Accidental public exposure of database',
      targetFormat: 'terraform',
      files: {
        'database.tf': `
resource "aws_db_instance" "bad_postgres" {
  identifier          = "leaky-db"
  engine              = "postgres"
  publicly_accessible = true
}

resource "aws_security_group" "bad_sg" {
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
        `.trim(),
      },
    };

    const res = registry.validateTemplate(regressedTemplate);
    expect(res.valid).toBe(false);
    expect(res.detectedIssues.length).toBeGreaterThanOrEqual(2);
    expect(res.detectedIssues[0]).toContain('0.0.0.0/0');
    expect(res.detectedIssues[1]).toContain('publicly_accessible set to true');
  });

  it('scaffolds chosen template files cleanly into project output map', () => {
    const files = registry.scaffoldTemplate('public-api-service');
    expect(files['main.tf']).toBeDefined();
    expect(files['main.tf']).toContain('resource "aws_lb" "api_alb"');
    expect(files['main.tf']).toContain('resource "aws_security_group" "alb_sg"');
  });
});
