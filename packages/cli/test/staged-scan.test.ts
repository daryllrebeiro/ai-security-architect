import { describe, it, expect } from 'vitest';
import { executeScan } from '../src/commands/scan.js';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('Milestone 2.2: Staged Git Pre-Commit Scanning Mode', () => {
  it('runs scan in staged mode and processes workspace gracefully', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-arch-staged-test-'));
    try {
      // Create minimal repository fixture
      fs.writeFileSync(
        path.join(tempDir, 'main.tf'),
        `
        resource "aws_s3_bucket" "b" {
          bucket = "my-test-bucket"
        }
        `
      );

      const result = await executeScan({
        path: tempDir,
        staged: true,
        silent: true,
      });

      expect(result).toBeDefined();
      expect(result.repository).toBeDefined();
      expect(result.attackPaths).toBeDefined();
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
