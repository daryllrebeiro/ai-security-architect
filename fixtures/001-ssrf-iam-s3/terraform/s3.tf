resource "aws_s3_bucket" "customer_pii" {
  bucket = "enterprise-production-customer-pii"

  tags = {
    DataClassification = "CONFIDENTIAL_PII"
    Environment        = "production"
    ContainsSensitive  = "true"
  }
}
