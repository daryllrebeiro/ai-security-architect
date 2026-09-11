import * as crypto from 'node:crypto';
import * as path from 'node:path';

export interface ExtractionWorkerPayload {
  filePath: string;
  content: string;
  options?: {
    extractTokens?: boolean;
    scanKeywords?: string[];
  };
}

export interface ExtractionWorkerResult {
  filePath: string;
  contentSha256: string;
  lineCount: number;
  detectedLanguage: string;
  tokensFound: string[];
  extractedIdentifiers: string[];
}

export function extractFileData(payload: ExtractionWorkerPayload): ExtractionWorkerResult {
  const { filePath, content, options } = payload;
  const contentSha256 = crypto.createHash('sha256').update(content, 'utf8').digest('hex');
  const lineCount = content.split(/\r?\n/).length;

  const ext = path.extname(filePath).toLowerCase();
  let detectedLanguage = 'plaintext';
  if (['.ts', '.tsx', '.js', '.jsx'].includes(ext)) detectedLanguage = 'typescript';
  else if (['.tf', '.hcl'].includes(ext)) detectedLanguage = 'terraform';
  else if (['.yaml', '.yml'].includes(ext)) detectedLanguage = 'yaml';
  else if (['.json'].includes(ext)) detectedLanguage = 'json';
  else if (['.java'].includes(ext)) detectedLanguage = 'java';
  else if (['.py'].includes(ext)) detectedLanguage = 'python';

  const tokensFound: string[] = [];
  const scanKeywords = options?.scanKeywords ?? [
    'aws_s3_bucket',
    'aws_iam_role',
    'kind: Deployment',
    'kind: Service',
    'password',
    'secret',
    'api_key',
  ];

  for (const kw of scanKeywords) {
    if (content.includes(kw)) {
      tokensFound.push(kw);
    }
  }

  // Extract identifiers via regex
  const extractedIdentifiers: string[] = [];
  const identMatches = content.match(/[A-Za-z_][A-Za-z0-9_]{3,}/g);
  if (identMatches) {
    const unique = new Set(identMatches);
    for (const id of unique) {
      if (extractedIdentifiers.length >= 50) break;
      extractedIdentifiers.push(id);
    }
  }

  return {
    filePath,
    contentSha256,
    lineCount,
    detectedLanguage,
    tokensFound,
    extractedIdentifiers,
  };
}

export default function run(payload: ExtractionWorkerPayload): ExtractionWorkerResult {
  return extractFileData(payload);
}
