resource "null_resource" "codacy_checkov_canary" {
  triggers = {
    marker = "harmless"
  }
}
