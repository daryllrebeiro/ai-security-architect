resource "aws_s3_bucket" "prod_release_bucket" {
  bucket = "enterprise-production-artifacts-release"

  tags = {
    Environment = "production"
    DataClass   = "production-builds"
  }
}

resource "aws_iam_role" "cicd_deploy_role" {
  name = "cicd-deploy-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "cicd_s3_wildcard" {
  name = "cicd-s3-wildcard"
  role = aws_iam_role.cicd_deploy_role.id

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
