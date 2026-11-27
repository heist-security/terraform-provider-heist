data "heist_credentials" "all" {}

output "unlinked_credentials" {
  value = [for c in data.heist_credentials.all.credentials : c.id if length(c.applications) == 0]
}
