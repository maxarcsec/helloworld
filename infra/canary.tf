# Trigger a fresh analysis after enabling Checkov in the controlled coding standard.
resource "null_resource" "codacy_checkov_canary" {
  triggers = {
    marker = "harmless"
  }
}
