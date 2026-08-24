import {
  createEvidence,
  type Finding,
  type Evidence,
} from '@ai-security-architect/core';
import type { AnalyzerContext, SecurityAnalyzer, AnalyzerResult } from '../types.js';
import type { EphemeralWorkspace } from '@ai-security-architect/ingestion';

interface KnownVulnerability {
  ecosystem: 'maven' | 'npm';
  packageName: string;
  vulnerableVersionPattern: RegExp;
  cve: string;
  cwe: string;
  title: string;
  severity: 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
}

export class ScaDependencyAnalyzer implements SecurityAnalyzer {
  public readonly name = 'ScaDependencyAnalyzer';

  private readonly knownVulns: KnownVulnerability[] = [
    {
      ecosystem: 'maven',
      packageName: 'org.apache.logging.log4j:log4j-core',
      vulnerableVersionPattern: /^2\.(?:[0-9]|1[0-4])\./,
      cve: 'CVE-2021-44228',
      cwe: 'CWE-502',
      title: 'Apache Log4j2 Remote Code Execution (Log4Shell)',
      severity: 'CRITICAL',
      description: 'JNDI lookup feature in Log4j allows unauthenticated remote code execution via attacker-controlled log messages.',
    },
    {
      ecosystem: 'maven',
      packageName: 'org.springframework:spring-beans',
      vulnerableVersionPattern: /^5\.(?:[0-2]\.|3\.(?:[0-9]|1[0-7]))/,
      cve: 'CVE-2022-22965',
      cwe: 'CWE-94',
      title: 'Spring Framework RCE via Data Binding (Spring4Shell)',
      severity: 'CRITICAL',
      description: 'Spring MVC / WebFlux application running on JDK 9+ allows RCE via data binding ClassLoader access.',
    },
    {
      ecosystem: 'npm',
      packageName: 'axios',
      vulnerableVersionPattern: /^0\.(?:[0-9]|1[0-8])\./,
      cve: 'CVE-2020-28168',
      cwe: 'CWE-918',
      title: 'Axios SSRF via Proxy Configuration Bypass',
      severity: 'HIGH',
      description: 'Axios allows attackers to bypass proxy settings through server response headers.',
    },
  ];

  public async supports(_workspace: EphemeralWorkspace, fileList: string[]): Promise<boolean> {
    return fileList.some((f) => f.endsWith('pom.xml') || f.endsWith('package.json'));
  }

  public async analyze(context: AnalyzerContext, _fileList: string[]): Promise<AnalyzerResult> {
    const findings: Finding[] = [];
    const evidenceList: Evidence[] = [];

    const dependencyAssets = context.discoveredAssets.filter((a) => a.type === 'DEPENDENCY');

    for (const depAsset of dependencyAssets) {
      const depName = depAsset.name;
      const version = String(depAsset.metadata.version || '');
      const ecosystem = depAsset.metadata.ecosystem as 'maven' | 'npm';
      const manifestPath = String(depAsset.metadata.manifestPath || 'pom.xml');

      for (const vuln of this.knownVulns) {
        if (vuln.ecosystem === ecosystem && vuln.packageName === depName) {
          if (vuln.vulnerableVersionPattern.test(version)) {
            let snippet = `${depName}:${version}`;
            try {
              snippet = await context.workspace.readSafeFile(manifestPath);
            } catch {
              // fallback to snippet string
            }

            const evidence = createEvidence({
              id: `ev-sca-${vuln.cve.toLowerCase()}-${depAsset.id}`,
              tenantId: context.tenantId,
              sourceType: 'DEPENDENCY_LOCKFILE',
              repository: context.repository,
              filePath: manifestPath,
              lineStart: 1,
              lineEnd: 10,
              snippet,
              scanner: 'ScaDependencyAnalyzer',
            });
            evidenceList.push(evidence);

            findings.push({
              id: `finding-sca-${vuln.cve.toLowerCase()}-${depAsset.id}`,
              tenantId: context.tenantId,
              assetId: depAsset.id,
              category: 'VULNERABLE_DEPENDENCY',
              ruleId: vuln.cve,
              title: `${vuln.title} in ${depName}`,
              description: vuln.description,
              severity: vuln.severity,
              confidence: 'CERTAIN',
              scanner: 'ScaDependencyAnalyzer',
              cve: vuln.cve,
              cwe: vuln.cwe,
              evidence,
              remediationRecommendation: `Upgrade ${depName} to a patched version.`,
              metadata: { packageName: depName, currentVersion: version },
            });
          }
        }
      }
    }

    return { findings, evidence: evidenceList };
  }
}
