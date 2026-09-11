import * as diff from 'diff';
import * as yaml from 'yaml';
import type { EphemeralWorkspace } from '@ai-security-architect/ingestion';
import type { RemediationPatch } from '@ai-security-architect/core';
import { PatchApplicationError } from './types.js';

export class PatchApplier {
  public async applyPatches(
    workspace: EphemeralWorkspace,
    patches: RemediationPatch[]
  ): Promise<string[]> {
    const backupMap = new Map<string, string | null>(); // path -> originalContent (null if created)
    const modifiedFiles: string[] = [];

    try {
      for (const patch of patches) {
        if (patch.action === 'MODIFY') {
          let originalContent = '';
          try {
            originalContent = await workspace.readSafeFile(patch.filePath);
          } catch (err) {
            throw new PatchApplicationError(
              `Target file for modification does not exist: ${(err as Error).message}`,
              patch.filePath
            );
          }

          if (!backupMap.has(patch.filePath)) {
            backupMap.set(patch.filePath, originalContent);
          }

          const rawPatch = patch.unifiedDiff || patch.diff;
          if (!rawPatch) {
            throw new PatchApplicationError('No diff payload provided in patch', patch.filePath);
          }

          const newContent = this.applyUnifiedDiff(originalContent, rawPatch, patch.filePath);

          // Syntax Validation Pass
          this.validateSyntax(patch.filePath, newContent);

          await workspace.writeSafeFile(patch.filePath, newContent);
          modifiedFiles.push(patch.filePath);
        } else if (patch.action === 'CREATE') {
          if (!backupMap.has(patch.filePath)) {
            backupMap.set(patch.filePath, null);
          }

          const rawPatch = patch.unifiedDiff || patch.diff || '';
          const newContent = this.extractContentFromDiff(rawPatch);

          // Syntax Validation Pass
          this.validateSyntax(patch.filePath, newContent);

          await workspace.writeSafeFile(patch.filePath, newContent);
          modifiedFiles.push(patch.filePath);
        }
      }

      return Array.from(new Set(modifiedFiles));
    } catch (err) {
      // Roll back all modified files to original state on failure
      for (const [filePath, originalContent] of backupMap.entries()) {
        try {
          if (originalContent !== null) {
            await workspace.writeSafeFile(filePath, originalContent);
          }
        } catch {
          // Best effort rollback
        }
      }
      throw err;
    }
  }

  private applyUnifiedDiff(originalContent: string, patchText: string, filePath: string): string {
    try {
      const trimmed = patchText.trim();

      // If already a standard unified diff with @@ hunk header
      if (trimmed.includes('@@')) {
        let formatted = trimmed;
        if (!formatted.startsWith('---')) {
          formatted = `--- a/${filePath}\n+++ b/${filePath}\n${formatted}`;
        }

        const parsed = diff.parsePatch(formatted);
        if (parsed && parsed.length > 0 && parsed[0].hunks.length > 0) {
          const applied = diff.applyPatch(originalContent, formatted, { fuzzFactor: 2 });
          if (typeof applied === 'string') {
            return applied;
          }
        }

        throw new PatchApplicationError(
          'Patch context mismatch: hunk could not be applied within fuzz tolerance',
          filePath,
          trimmed.slice(0, 200),
          originalContent.slice(0, 200)
        );
      }

      // If simplified diff lines (starting with - and +) without @@ header:
      const lines = trimmed.split('\n');
      const removedLines: string[] = [];
      const addedLines: string[] = [];

      for (const l of lines) {
        if (l.startsWith('-')) removedLines.push(l.substring(1).trim());
        else if (l.startsWith('+')) addedLines.push(l.substring(1));
      }

      if (removedLines.length === 0) {
        throw new PatchApplicationError('No removable lines found in patch', filePath);
      }

      // Search original content for removed lines block (normalizing whitespace)
      const origLines = originalContent.split('\n');
      const norm = (s: string) => s.replace(/\s+/g, ' ').trim();
      let matchIdx = -1;

      for (let i = 0; i < origLines.length; i++) {
        if (norm(origLines[i]) === norm(removedLines[0])) {
          let allMatch = true;
          for (let j = 1; j < removedLines.length; j++) {
            if (i + j >= origLines.length || norm(origLines[i + j]) !== norm(removedLines[j])) {
              allMatch = false;
              break;
            }
          }
          if (allMatch) {
            matchIdx = i;
            break;
          }
        }
      }

      if (matchIdx === -1) {
        throw new PatchApplicationError(
          'Patch context mismatch: expected lines not found in target file',
          filePath,
          removedLines.join('\n'),
          originalContent.slice(0, 200)
        );
      }

      // Preserve indentation of original line
      const leadingWhitespace = origLines[matchIdx].match(/^\s*/)?.[0] || '';
      const formattedAdded = addedLines.map((line) => {
        if (line.startsWith(' ') || line.startsWith('\t')) return line;
        return leadingWhitespace + line;
      });

      origLines.splice(matchIdx, removedLines.length, ...formattedAdded);
      return origLines.join('\n');
    } catch (err) {
      if (err instanceof PatchApplicationError) {
        throw err;
      }
      throw new PatchApplicationError((err as Error).message, filePath);
    }
  }

  private validateSyntax(filePath: string, content: string): void {
    if (filePath.endsWith('.yaml') || filePath.endsWith('.yml')) {
      try {
        yaml.parse(content);
      } catch (err) {
        throw new PatchApplicationError(
          `YAML syntax validation failed post-patch: ${(err as Error).message}`,
          filePath,
          undefined,
          content.slice(0, 200)
        );
      }
    } else if (filePath.endsWith('.tf')) {
      // Basic structural validator for Terraform HCL (balanced braces outside quotes)
      let openBraces = 0;
      let openBrackets = 0;
      let inString = false;
      let stringChar = '';
      let isEscaped = false;

      for (let i = 0; i < content.length; i++) {
        const char = content[i];
        if (inString) {
          if (isEscaped) {
            isEscaped = false;
          } else if (char === '\\') {
            isEscaped = true;
          } else if (char === stringChar) {
            inString = false;
          }
          continue;
        }

        if (char === '"' || char === "'") {
          inString = true;
          stringChar = char;
        } else if (char === '{') {
          openBraces++;
        } else if (char === '}') {
          openBraces--;
          if (openBraces < 0) {
            throw new PatchApplicationError(
              'Terraform HCL syntax error: unexpected closing brace "}"',
              filePath,
              undefined,
              content.slice(Math.max(0, i - 50), i + 50)
            );
          }
        } else if (char === '[') {
          openBrackets++;
        } else if (char === ']') {
          openBrackets--;
          if (openBrackets < 0) {
            throw new PatchApplicationError(
              'Terraform HCL syntax error: unexpected closing bracket "]"',
              filePath,
              undefined,
              content.slice(Math.max(0, i - 50), i + 50)
            );
          }
        }
      }

      if (openBraces !== 0) {
        throw new PatchApplicationError(
          `Terraform HCL syntax error: unclosed brace (missing ${openBraces} "}")`,
          filePath
        );
      }
      if (openBrackets !== 0) {
        throw new PatchApplicationError(
          `Terraform HCL syntax error: unclosed bracket (missing ${openBrackets} "]")`,
          filePath
        );
      }
    }
  }

  private extractContentFromDiff(diffText: string): string {
    return diffText
      .split('\n')
      .filter((line) => line.startsWith('+') && !line.startsWith('+++'))
      .map((line) => line.substring(1))
      .join('\n');
  }
}
