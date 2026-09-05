import * as fs from 'node:fs';
import * as path from 'node:path';
import type { SecurityGraphSnapshot } from './types.js';

export interface GraphSnapshotRepositoryOptions {
  storageDir?: string;
}

export interface GraphSnapshotLookup {
  tenantId: string;
  sourceFingerprint: string;
}

export class GraphSnapshotRepository {
  private readonly storageDir: string;

  constructor(options: GraphSnapshotRepositoryOptions = {}) {
    this.storageDir = options.storageDir ?? path.resolve('.graph-snapshot-store');
  }

  public save(snapshot: SecurityGraphSnapshot): void {
    if (!snapshot.sourceFingerprint) {
      throw new Error('Graph snapshots must include a source fingerprint');
    }

    this.ensureReady();
    const filePath = this.snapshotPath(snapshot.tenantId, snapshot.sourceFingerprint);
    fs.writeFileSync(filePath, JSON.stringify(snapshot, null, 2), 'utf8');
  }

  public load(lookup: GraphSnapshotLookup): SecurityGraphSnapshot | undefined {
    this.ensureReady();
    const filePath = this.snapshotPath(lookup.tenantId, lookup.sourceFingerprint);

    try {
      const snapshot = JSON.parse(fs.readFileSync(filePath, 'utf8')) as SecurityGraphSnapshot;
      if (snapshot.tenantId !== lookup.tenantId || snapshot.sourceFingerprint !== lookup.sourceFingerprint) {
        return undefined;
      }
      return snapshot;
    } catch {
      return undefined;
    }
  }

  public invalidate(lookup: GraphSnapshotLookup): boolean {
    const filePath = this.snapshotPath(lookup.tenantId, lookup.sourceFingerprint);
    try {
      fs.unlinkSync(filePath);
      return true;
    } catch {
      return false;
    }
  }

  private ensureReady(): void {
    fs.mkdirSync(this.storageDir, { recursive: true });
  }

  private snapshotPath(tenantId: string, sourceFingerprint: string): string {
    const key = `${tenantId}-${sourceFingerprint}`.replace(/[^a-zA-Z0-9._-]/g, '_');
    return path.join(this.storageDir, `${key}.json`);
  }
}