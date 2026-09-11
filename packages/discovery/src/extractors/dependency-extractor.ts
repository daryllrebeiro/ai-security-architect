import {
  createEvidence,
  type Asset,
  type Relationship,
  type Evidence,
  type Finding,
} from '@ai-security-architect/core';
import type { DiscoveryContext, DiscoveryExtractor, DiscoveryResult } from '../types.js';
import type { EphemeralWorkspace } from '@ai-security-architect/ingestion';

export interface KnownCveAdvisory {
  ecosystem: 'npm' | 'maven' | 'pypi';
  packageName: string;
  vulnerableCheck: (ver: string) => boolean;
  cveId: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  description: string;
}

export const KNOWN_CVE_ADVISORIES: KnownCveAdvisory[] = [
  {
    ecosystem: 'maven',
    packageName: 'org.apache.logging.log4j:log4j-core',
    vulnerableCheck: (ver) => ver.startsWith('2.') && !ver.startsWith('2.15') && !ver.startsWith('2.16') && !ver.startsWith('2.17'),
    cveId: 'CVE-2021-44228',
    title: 'Log4Shell: Remote Code Execution via JNDI Injection',
    severity: 'CRITICAL',
    description: 'Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.',
  },
  {
    ecosystem: 'maven',
    packageName: 'org.springframework:spring-beans',
    vulnerableCheck: (ver) => ver.startsWith('5.3.') && parseInt(ver.split('.')[2] || '0', 10) < 18,
    cveId: 'CVE-2022-22965',
    title: 'Spring4Shell: Remote Code Execution in Spring Framework',
    severity: 'CRITICAL',
    description: 'Spring Framework RCE via Data Binding on JDK 9+ allowing arbitrary classloader manipulation.',
  },
  {
    ecosystem: 'npm',
    packageName: 'jsonwebtoken',
    vulnerableCheck: (ver) => {
      const clean = ver.replace(/[\^~>=<]/g, '').trim();
      const major = parseInt(clean.split('.')[0] || '0', 10);
      return major > 0 && major < 9;
    },
    cveId: 'CVE-2022-23529',
    title: 'Arbitrary File Write / Code Execution in jsonwebtoken secretOrPublicKey',
    severity: 'HIGH',
    description: 'jsonwebtoken allows insecure key retrieval leading to arbitrary code execution if untrusted input is passed.',
  },
  {
    ecosystem: 'pypi',
    packageName: 'pyyaml',
    vulnerableCheck: (ver) => {
      const clean = ver.replace(/[\^~>=<]/g, '').trim();
      const major = parseFloat(clean);
      return major < 5.4;
    },
    cveId: 'CVE-2020-14343',
    title: 'Arbitrary Code Execution in PyYAML FullLoader',
    severity: 'CRITICAL',
    description: 'PyYAML allows untrusted YAML deserialization executing arbitrary Python commands.',
  },
];

export class DependencyExtractor implements DiscoveryExtractor {
  public readonly name = 'DependencyExtractor';

  public async supports(_workspace: EphemeralWorkspace, fileList: string[]): Promise<boolean> {
    return fileList.some(
      (f) =>
        f.endsWith('pom.xml') ||
        f.endsWith('package.json') ||
        f.endsWith('package-lock.json') ||
        f.endsWith('requirements.txt') ||
        f.endsWith('pnpm-lock.yaml')
    );
  }

  public async extract(context: DiscoveryContext, fileList: string[]): Promise<DiscoveryResult> {
    const assets: Asset[] = [];
    const relationships: Relationship[] = [];
    const evidenceList: Evidence[] = [];
    const findings: Finding[] = [];

    // 1. Parse package.json & package-lock.json
    const packageFiles = fileList.filter(
      (f) => (f.endsWith('package.json') || f.endsWith('package-lock.json')) && !f.includes('node_modules')
    );

    for (const filePath of packageFiles) {
      try {
        const content = await context.workspace.readSafeFile(filePath);
        const parsed = JSON.parse(content);

        let depsMap: Record<string, string> = {};

        if (parsed.packages && typeof parsed.packages === 'object') {
          // npm lockfile v2/v3
          for (const [pkgPath, pkgMeta] of Object.entries(parsed.packages)) {
            if (pkgPath.startsWith('node_modules/') && (pkgMeta as any).version) {
              const name = pkgPath.replace('node_modules/', '');
              depsMap[name] = (pkgMeta as any).version;
            }
          }
        } else if (parsed.dependencies || parsed.devDependencies) {
          // package.json
          depsMap = {
            ...(parsed.dependencies || {}),
            ...(parsed.devDependencies || {}),
          };
        }

        const evidence = createEvidence({
          id: `ev-pkg-${filePath.replace(/[^a-zA-Z0-9]/g, '_')}`,
          tenantId: context.tenantId,
          sourceType: 'DEPENDENCY_LOCKFILE',
          repository: context.repository,
          filePath,
          lineStart: 1,
          lineEnd: content.split('\n').length,
          snippet: content.substring(0, 500),
          scanner: 'DependencyExtractor',
        });
        evidenceList.push(evidence);

        for (const [depName, versionRaw] of Object.entries(depsMap)) {
          const version = String(versionRaw);
          const depAssetId = `asset-dep-npm-${depName.replace(/[^a-zA-Z0-9]/g, '_')}`;

          const advisory = KNOWN_CVE_ADVISORIES.find(
            (a) => a.ecosystem === 'npm' && a.packageName === depName && a.vulnerableCheck(version)
          );

          const isVuln = Boolean(advisory);
          const tags = ['dependency', 'npm'];
          if (isVuln) {
            tags.push('vulnerable', `cve:${advisory!.cveId}`, `severity:${advisory!.severity}`);
          }

          assets.push({
            id: depAssetId,
            tenantId: context.tenantId,
            type: 'DEPENDENCY',
            name: depName,
            environment: 'npm',
            isPublic: false,
            isSensitiveData: false,
            criticality: isVuln ? advisory!.severity : 'LOW',
            metadata: {
              ecosystem: 'npm',
              version,
              manifestPath: filePath,
              vulnerability: advisory ? advisory.cveId : undefined,
            },
            tags,
          });

          if (advisory) {
            findings.push({
              id: `finding-${advisory.cveId.toLowerCase()}-${depAssetId}`,
              tenantId: context.tenantId,
              assetId: depAssetId,
              category: 'VULNERABLE_DEPENDENCY',
              ruleId: `vuln-dep-${advisory.cveId.toLowerCase()}`,
              severity: advisory.severity,
              confidence: 'CERTAIN',
              scanner: 'DependencyExtractor',
              title: `${advisory.cveId}: ${advisory.title}`,
              description: advisory.description,
              cve: advisory.cveId,
              remediationRecommendation: `Upgrade ${depName} to secure version.`,
              evidence,
              metadata: {},
            });
          }
        }
      } catch {
        continue;
      }
    }

    // 2. Parse pom.xml
    const pomFiles = fileList.filter((f) => f.endsWith('pom.xml'));

    for (const filePath of pomFiles) {
      try {
        const content = await context.workspace.readSafeFile(filePath);
        const depBlockRegex = /<dependency>([\s\S]*?)<\/dependency>/g;
        let blockMatch: RegExpExecArray | null;

        const evidence = createEvidence({
          id: `ev-mvn-${filePath.replace(/[^a-zA-Z0-9]/g, '_')}`,
          tenantId: context.tenantId,
          sourceType: 'DEPENDENCY_LOCKFILE',
          repository: context.repository,
          filePath,
          lineStart: 1,
          lineEnd: content.split('\n').length,
          snippet: content.substring(0, 500),
          scanner: 'DependencyExtractor',
        });
        evidenceList.push(evidence);

        while ((blockMatch = depBlockRegex.exec(content)) !== null) {
          const block = blockMatch[1];
          const groupMatch = /<groupId>([^<]+)<\/groupId>/.exec(block);
          const artifactMatch = /<artifactId>([^<]+)<\/artifactId>/.exec(block);
          const versionMatch = /<version>([^<]+)<\/version>/.exec(block);

          if (!groupMatch || !artifactMatch) continue;

          const groupId = groupMatch[1].trim();
          const artifactId = artifactMatch[1].trim();
          const version = versionMatch ? versionMatch[1].trim() : 'inherited';

          const depFullName = `${groupId}:${artifactId}`;
          const depAssetId = `asset-dep-mvn-${groupId.replace(/[^a-zA-Z0-9]/g, '_')}-${artifactId.replace(/[^a-zA-Z0-9]/g, '_')}`;

          const advisory = KNOWN_CVE_ADVISORIES.find(
            (a) =>
              a.ecosystem === 'maven' &&
              (a.packageName === depFullName || a.packageName.endsWith(`:${artifactId}`)) &&
              a.vulnerableCheck(version)
          );

          const isVuln = Boolean(advisory);
          const tags = ['dependency', 'maven'];
          if (isVuln) {
            tags.push('vulnerable', `cve:${advisory!.cveId}`, `severity:${advisory!.severity}`);
          }

          assets.push({
            id: depAssetId,
            tenantId: context.tenantId,
            type: 'DEPENDENCY',
            name: depFullName,
            environment: 'maven',
            isPublic: false,
            isSensitiveData: false,
            criticality: isVuln ? advisory!.severity : 'LOW',
            metadata: {
              ecosystem: 'maven',
              groupId,
              artifactId,
              version,
              manifestPath: filePath,
              vulnerability: advisory ? advisory.cveId : undefined,
            },
            tags,
          });

          if (advisory) {
            findings.push({
              id: `finding-${advisory.cveId.toLowerCase()}-${depAssetId}`,
              tenantId: context.tenantId,
              assetId: depAssetId,
              category: 'VULNERABLE_DEPENDENCY',
              ruleId: `vuln-dep-${advisory.cveId.toLowerCase()}`,
              severity: advisory.severity,
              confidence: 'CERTAIN',
              scanner: 'DependencyExtractor',
              title: `${advisory.cveId}: ${advisory.title}`,
              description: advisory.description,
              cve: advisory.cveId,
              remediationRecommendation: `Upgrade ${depFullName} to a patched release.`,
              evidence,
              metadata: {},
            });
          }
        }
      } catch {
        continue;
      }
    }

    // 3. Parse requirements.txt
    const reqFiles = fileList.filter((f) => f.endsWith('requirements.txt'));

    for (const filePath of reqFiles) {
      try {
        const content = await context.workspace.readSafeFile(filePath);
        const lines = content.split('\n');

        const evidence = createEvidence({
          id: `ev-py-${filePath.replace(/[^a-zA-Z0-9]/g, '_')}`,
          tenantId: context.tenantId,
          sourceType: 'DEPENDENCY_LOCKFILE',
          repository: context.repository,
          filePath,
          lineStart: 1,
          lineEnd: lines.length,
          snippet: content.substring(0, 500),
          scanner: 'DependencyExtractor',
        });
        evidenceList.push(evidence);

        for (const rawLine of lines) {
          const line = rawLine.trim();
          if (!line || line.startsWith('#')) continue;

          const match = /^([a-zA-Z0-9_\-\.]+)(?:==|>=|<=|~=)(.+)$/.exec(line);
          if (match) {
            const depName = match[1].toLowerCase();
            const version = match[2].trim();
            const depAssetId = `asset-dep-py-${depName.replace(/[^a-zA-Z0-9]/g, '_')}`;

            const advisory = KNOWN_CVE_ADVISORIES.find(
              (a) => a.ecosystem === 'pypi' && a.packageName === depName && a.vulnerableCheck(version)
            );

            const isVuln = Boolean(advisory);
            const tags = ['dependency', 'pypi'];
            if (isVuln) {
              tags.push('vulnerable', `cve:${advisory!.cveId}`, `severity:${advisory!.severity}`);
            }

            assets.push({
              id: depAssetId,
              tenantId: context.tenantId,
              type: 'DEPENDENCY',
              name: depName,
              environment: 'pypi',
              isPublic: false,
              isSensitiveData: false,
              criticality: isVuln ? advisory!.severity : 'LOW',
              metadata: {
                ecosystem: 'pypi',
                version,
                manifestPath: filePath,
                vulnerability: advisory ? advisory.cveId : undefined,
              },
              tags,
            });

            if (advisory) {
              findings.push({
                id: `finding-${advisory.cveId.toLowerCase()}-${depAssetId}`,
                tenantId: context.tenantId,
                assetId: depAssetId,
                category: 'VULNERABLE_DEPENDENCY',
                ruleId: `vuln-dep-${advisory.cveId.toLowerCase()}`,
                severity: advisory.severity,
                confidence: 'CERTAIN',
                scanner: 'DependencyExtractor',
                title: `${advisory.cveId}: ${advisory.title}`,
                description: advisory.description,
                cve: advisory.cveId,
                remediationRecommendation: `Upgrade ${depName} to secure release.`,
                evidence,
                metadata: {},
              });
            }
          }
        }
      } catch {
        continue;
      }
    }

    return { assets, relationships, evidence: evidenceList, findings };
  }
}
