import { FormalVerificationEngine } from '@ai-security-architect/attackpath';
import { PavedRoadTemplate, PavedRoadValidationResult } from './types.js';

export const BUILTIN_PAVED_ROAD_TEMPLATES: PavedRoadTemplate[] = [
  {
    name: 'public-api-service',
    title: 'Public API Service behind Application Load Balancer with Scoped IAM',
    category: 'API_SERVICE',
    description: 'Reference architecture for a containerized microservice exposed via ALB with TLS termination, private subnet placement, and least-privilege IAM task role.',
    targetFormat: 'terraform',
    files: {
      'main.tf': `
resource "aws_lb" "api_alb" {
  name               = "service-public-alb"
  internal           = false
  load_balancer_type = "application"
  subnets            = var.public_subnets
  security_groups    = [aws_security_group.alb_sg.id]
}

resource "aws_security_group" "alb_sg" {
  name   = "alb-security-group"
  vpc_id = var.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    security_groups = [aws_security_group.app_sg.id]
  }
}

resource "aws_security_group" "app_sg" {
  name   = "app-service-sg"
  vpc_id = var.vpc_id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }
}
      `.trim(),
    },
  },
  {
    name: 'isolated-worker',
    title: 'Private Background Worker Consuming SQS with Zero Public Ingress',
    category: 'BACKGROUND_WORKER',
    description: 'Reference architecture for asynchronous queue-driven workers in strictly private subnets with no public IP, zero inbound firewall ports, and encrypted messaging.',
    targetFormat: 'terraform',
    files: {
      'worker.tf': `
resource "aws_sqs_queue" "jobs" {
  name                      = "async-jobs-queue"
  kms_master_key_id         = "alias/aws/sqs"
  message_retention_seconds = 86400
}

resource "aws_security_group" "worker_sg" {
  name        = "isolated-worker-sg"
  description = "No inbound rules allowed"
  vpc_id      = var.vpc_id

  # Zero ingress rules
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
}
      `.trim(),
    },
  },
  {
    name: 'secure-db-access',
    title: 'Private RDS Aurora Cluster with IAM Authentication & Restricted VPC Security Groups',
    category: 'DATA_STORAGE',
    description: 'Formally proven secure database topology: placed in isolated DB subnets, strictly unroutable from internet, with access permitted only from authorized app security groups.',
    targetFormat: 'terraform',
    formalInvariant: {
      invariant: {
        name: 'INV-PAVED-ROAD-DB-ISOLATION',
        crownJewelAssetId: 'asset-rds-db',
        entryNodeId: 'asset-internet',
      },
      subgraph: {
        nodeIds: ['asset-internet', 'asset-alb', 'asset-app', 'asset-rds-db', 'asset-internal-mgmt'],
        configurationVariables: ['enable_read_replica', 'enable_vpc_peering'],
        edges: [
          { id: 'e1', fromAssetId: 'asset-internet', toAssetId: 'asset-alb' },
          { id: 'e2', fromAssetId: 'asset-alb', toAssetId: 'asset-app' },
          {
            id: 'e3-mgmt',
            fromAssetId: 'asset-internal-mgmt',
            toAssetId: 'asset-rds-db',
            conditionVar: 'enable_vpc_peering',
          },
        ],
      },
    },
    files: {
      'database.tf': `
resource "aws_db_instance" "postgres" {
  identifier             = "production-secure-postgres"
  allocated_storage      = 50
  engine                 = "postgres"
  instance_class         = "db.r6g.large"
  publicly_accessible    = false # STRICT GUARDRAIL
  db_subnet_group_name   = aws_db_subnet_group.private_subnets.name
  vpc_security_group_ids = [aws_security_group.db_sg.id]
  iam_database_authentication_enabled = true
}

resource "aws_security_group" "db_sg" {
  name   = "private-database-sg"
  vpc_id = var.vpc_id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app_sg.id]
  }
}
      `.trim(),
    },
  },
];

export class PavedRoadRegistry {
  private templates: Map<string, PavedRoadTemplate> = new Map();
  private formalVerifier = new FormalVerificationEngine();

  constructor(customTemplates: PavedRoadTemplate[] = []) {
    for (const t of BUILTIN_PAVED_ROAD_TEMPLATES) {
      this.templates.set(t.name, t);
    }
    for (const ct of customTemplates) {
      this.templates.set(ct.name, ct);
    }
  }

  listTemplates(): PavedRoadTemplate[] {
    return Array.from(this.templates.values());
  }

  getTemplate(name: string): PavedRoadTemplate | undefined {
    return this.templates.get(name);
  }

  /**
   * CI Validation Harness: Verifies that a template introduces zero attack paths and satisfies formal invariants
   */
  validateTemplate(template: PavedRoadTemplate): PavedRoadValidationResult {
    const issues: string[] = [];
    let formalProofVerified = false;
    let formalProofStatus: string | undefined;

    // 1. Static Antipattern Scan over template files
    for (const [filename, content] of Object.entries(template.files)) {
      // Antipattern 1: 0.0.0.0/0 on database or SSH ports
      if (content.includes('0.0.0.0/0') && (content.includes('5432') || content.includes('3306') || content.includes('port = 22'))) {
        issues.push(`Critical Antipattern in ${filename}: Direct public internet ingress (0.0.0.0/0) allowed on sensitive port.`);
      }

      // Antipattern 2: publicly_accessible = true
      if (/publicly_accessible\s*=\s*true/i.test(content)) {
        issues.push(`Critical Antipattern in ${filename}: Database publicly_accessible set to true.`);
      }

      // Antipattern 3: Wildcard IAM
      if (content.includes('"*"') && content.includes('Action')) {
        issues.push(`High Antipattern in ${filename}: Over-privileged wildcard IAM Action ("*") found.`);
      }
    }

    // 2. Formal Invariant Verification if configured
    if (template.formalInvariant) {
      const { subgraph, invariant } = template.formalInvariant;
      const proofResult = this.formalVerifier.verifyInvariant(subgraph, invariant);

      if (proofResult.provenSafe) {
        formalProofVerified = true;
        formalProofStatus = `Formally Proven UNSAT Across ${proofResult.totalConfigurationSpace} Configurations (Invariant: ${invariant.name})`;
      } else {
        issues.push(`Formal Verification Failed: Counterexample found producing exposure (${JSON.stringify(proofResult.counterexample)}).`);
        formalProofStatus = 'FAILED: Counterexample Found';
      }
    }

    return {
      templateName: template.name,
      valid: issues.length === 0,
      detectedIssues: issues,
      formalProofVerified,
      formalProofStatus,
    };
  }

  /**
   * Scaffolds template files into an object map (or disk structure)
   */
  scaffoldTemplate(templateName: string): Record<string, string> {
    const template = this.templates.get(templateName);
    if (!template) {
      throw new Error(`Paved road template "${templateName}" not found.`);
    }
    return { ...template.files };
  }
}
