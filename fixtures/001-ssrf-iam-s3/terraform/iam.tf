resource "aws_iam_role" "order_service_role" {
  name = "order-service-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRoleWithWebIdentity"
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E"
        }
        Condition = {
          StringEquals = {
            "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E:sub" = "system:serviceaccount:production:order-service-sa"
          }
        }
      }
    ]
  })
}

# VULNERABILITY: Overprivileged Wildcard Access to S3
resource "aws_iam_role_policy" "order_service_s3_wildcard" {
  name = "order-service-s3-wildcard"
  role = aws_iam_role.order_service_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:*"
        Resource = "*"
      }
    ]
  })
}
