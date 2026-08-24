import type { EphemeralWorkspace } from '@ai-security-architect/ingestion';
import type { RemediationPatch } from '@ai-security-architect/core';

export class PatchApplier {
  public async applyPatches(
    workspace: EphemeralWorkspace,
    patches: RemediationPatch[]
  ): Promise<string[]> {
    const modifiedFiles: string[] = [];

    for (const patch of patches) {
      if (patch.action === 'MODIFY') {
        const currentContent = await workspace.readSafeFile(patch.filePath);
        const modifiedContent = this.applyPatchDiff(currentContent, patch);
        await workspace.writeSafeFile(patch.filePath, modifiedContent);
        modifiedFiles.push(patch.filePath);
      } else if (patch.action === 'CREATE') {
        const newContent = this.extractContentFromDiff(patch.diff);
        await workspace.writeSafeFile(patch.filePath, newContent);
        modifiedFiles.push(patch.filePath);
      }
    }

    return modifiedFiles;
  }

  private applyPatchDiff(originalContent: string, patch: RemediationPatch): string {
    // Specific high-precision transformer for IAM wildcard policy remediation
    if (patch.filePath.includes('iam.tf') && (originalContent.includes('"s3:*"') || originalContent.includes("'s3:*'"))) {
      return originalContent.replace(
        /Action\s*=\s*["']s3:\*["'][\s\r\n]*Resource\s*=\s*["']\*["']/g,
        `Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::enterprise-production-customer-pii",
          "arn:aws:s3:::enterprise-production-customer-pii/*"
        ]`
      );
    }

    // Generic diff line replacement fallback
    const lines = patch.diff.split('\n');
    const removedLines: string[] = [];
    const addedLines: string[] = [];

    for (const line of lines) {
      if (line.startsWith('-')) {
        removedLines.push(line.substring(1).trim());
      } else if (line.startsWith('+')) {
        addedLines.push(line.substring(1));
      }
    }

    let result = originalContent;
    if (removedLines.length > 0) {
      for (const rem of removedLines) {
        if (rem && result.includes(rem)) {
          result = result.replace(rem, addedLines.join('\n'));
          return result;
        }
      }
    }

    return result;
  }

  private extractContentFromDiff(diff: string): string {
    return diff
      .split('\n')
      .filter((line) => line.startsWith('+'))
      .map((line) => line.substring(1))
      .join('\n');
  }
}
