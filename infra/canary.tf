# Trigger a fresh analysis after enabling Checkov in the controlled coding standard.
resource "null_resource" "codacy_checkov_canary" {
  triggers = {
    marker = "harmless"
  }
}

# Static-only intentionally insecure fixture. It is never deployed.
resource "aws_s3_bucket" "codacy_checkov_fixture" {
  bucket = "codacy-security-canary-never-deployed"
  acl    = "public-read"
}
