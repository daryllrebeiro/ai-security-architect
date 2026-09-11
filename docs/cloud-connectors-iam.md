# AWS Cloud Connectors - Least Privilege Read-Only IAM Policy

To enable live AWS runtime discovery and configuration drift detection in `ai-security-architect`, attach the following read-only IAM policy to the scan role or service account.

> **Zero Mutation Guarantee**: `ai-security-architect` strictly requires read-only metadata permissions (`List*` and `Get*`). It never modifies, deletes, or mutates any live cloud resources.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AiSecurityArchitectIamReadOnly",
      "Effect": "Allow",
      "Action": [
        "iam:ListRoles",
        "iam:GetRole",
        "iam:GetRolePolicy",
        "iam:ListRolePolicies",
        "iam:ListAttachedRolePolicies"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AiSecurityArchitectS3ReadOnly",
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketPolicy",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketAcl",
        "s3:GetPublicAccessBlock"
      ],
      "Resource": "*"
    }
  ]
}
```

## Security Best Practices
1. **Never grant write permissions**: Do not grant `s3:Put*`, `s3:Delete*`, `iam:Create*`, `iam:Attach*`, or `iam:Put*`.
2. **Use AWS IAM Roles for OIDC**: When running in GitHub Actions or Kubernetes, use OpenID Connect (OIDC) assume-role instead of static long-lived AWS secret access keys.
3. **Region Scoping**: If your deployment is confined to specific AWS regions (e.g. `us-east-1`), configure `AWS_DEFAULT_REGION` accordingly to minimize discovery latency.
