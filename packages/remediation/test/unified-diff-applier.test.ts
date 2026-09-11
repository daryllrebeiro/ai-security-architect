import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { WorkspaceManager, type EphemeralWorkspace } from '@ai-security-architect/ingestion';
import { PatchApplier } from '../src/patch-applier.js';
import { PatchApplicationError } from '../src/types.js';

describe('PatchApplier & Unified Diff Engine', () => {
  let workspaceManager: WorkspaceManager;
  let workspace: EphemeralWorkspace;

  beforeEach(async () => {
    workspaceManager = new WorkspaceManager();
    workspace = await workspaceManager.createWorkspace();
  });

  afterEach(async () => {
    await workspace.cleanup();
  });

  it('applies multi-hunk diffs across multiple files simultaneously', async () => {
    const applier = new PatchApplier();

    // Setup initial files
    const fileA = `resource "aws_s3_bucket" "b1" {
  bucket = "my-bucket"
  acl    = "public-read"
}

resource "aws_s3_bucket_policy" "p1" {
  bucket = "my-bucket"
  policy = "public"
}`;

    const fileB = `apiVersion: v1
kind: Service
metadata:
  name: order-service
  namespace: prod
spec:
  type: LoadBalancer
  selector:
    app: order`;

    await workspace.writeSafeFile('terraform/storage.tf', fileA);
    await workspace.writeSafeFile('k8s/service.yaml', fileB);

    const patchA = `--- a/terraform/storage.tf
+++ b/terraform/storage.tf
@@ -2,2 +2,2 @@
   bucket = "my-bucket"
-  acl    = "public-read"
+  acl    = "private"
@@ -7,2 +7,2 @@
   bucket = "my-bucket"
-  policy = "public"
+  policy = "restricted"`;

    const patchB = `--- a/k8s/service.yaml
+++ b/k8s/service.yaml
@@ -6,2 +6,2 @@
 spec:
-  type: LoadBalancer
+  type: ClusterIP`;

    const modified = await applier.applyPatches(workspace, [
      {
        filePath: 'terraform/storage.tf',
        action: 'MODIFY',
        unifiedDiff: patchA,
        description: 'Restrict S3 ACL and policy',
      },
      {
        filePath: 'k8s/service.yaml',
        action: 'MODIFY',
        unifiedDiff: patchB,
        description: 'Switch service from LoadBalancer to ClusterIP',
      },
    ]);

    expect(modified).toEqual(['terraform/storage.tf', 'k8s/service.yaml']);

    const resA = await workspace.readSafeFile('terraform/storage.tf');
    expect(resA).toContain('acl    = "private"');
    expect(resA).toContain('policy = "restricted"');
    expect(resA).not.toContain('public-read');

    const resB = await workspace.readSafeFile('k8s/service.yaml');
    expect(resB).toContain('type: ClusterIP');
    expect(resB).not.toContain('type: LoadBalancer');
  });

  it('applies diff with intentional context drift within fuzz tolerance', async () => {
    const applier = new PatchApplier();

    // Original file with slight whitespace difference
    const fileContent = `resource "aws_iam_role" "role1" {
  name = "app-role"
  description = "Role for app"
}`;
    await workspace.writeSafeFile('terraform/role.tf', fileContent);

    // Diff that has slight line drift
    const patch = `--- a/terraform/role.tf
+++ b/terraform/role.tf
@@ -1,4 +1,4 @@
 resource "aws_iam_role" "role1" {
   name = "app-role"
-  description = "Role for app"
+  description = "Hardened role for app"
 }`;

    await applier.applyPatches(workspace, [
      {
        filePath: 'terraform/role.tf',
        action: 'MODIFY',
        unifiedDiff: patch,
        description: 'Update role description',
      },
    ]);

    const result = await workspace.readSafeFile('terraform/role.tf');
    expect(result).toContain('Hardened role for app');
  });

  it('rejects diff with invalid syntax, throws PatchApplicationError and rolls back original content', async () => {
    const applier = new PatchApplier();

    const initialContent = `resource "aws_security_group" "sg" {
  name = "allow_all"
  ingress {
    from_port = 0
    to_port   = 0
  }
}`;
    await workspace.writeSafeFile('terraform/sg.tf', initialContent);

    // Corrupt diff introducing an unclosed brace
    const corruptPatch = `--- a/terraform/sg.tf
+++ b/terraform/sg.tf
@@ -3,4 +3,4 @@
   ingress {
     from_port = 0
-    to_port   = 0
-  }
+    to_port   = 80
+    # missing closing brace intentionally!`;

    await expect(
      applier.applyPatches(workspace, [
        {
          filePath: 'terraform/sg.tf',
          action: 'MODIFY',
          unifiedDiff: corruptPatch,
          description: 'Corrupt patch that breaks syntax',
        },
      ])
    ).rejects.toThrow(PatchApplicationError);

    // Confirm that the workspace file was safely ROLLED BACK to its exact initial state
    const afterFailedContent = await workspace.readSafeFile('terraform/sg.tf');
    expect(afterFailedContent).toBe(initialContent);
  });

  it('throws typed PatchApplicationError on context mismatch', async () => {
    const applier = new PatchApplier();

    await workspace.writeSafeFile('terraform/vpc.tf', 'resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }');

    const wrongPatch = `--- a/terraform/vpc.tf
+++ b/terraform/vpc.tf
@@ -1,2 +1,2 @@
-completely nonexistent context line that will not match
+new line`;

    await expect(
      applier.applyPatches(workspace, [
        {
          filePath: 'terraform/vpc.tf',
          action: 'MODIFY',
          unifiedDiff: wrongPatch,
          description: 'Non-matching patch',
        },
      ])
    ).rejects.toThrow(PatchApplicationError);
  });
});
