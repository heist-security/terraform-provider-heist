data "heist_credential" "admin" {
  id = "3f6c2a1b-7d4e-4c8a-9b0f-1e2d3c4b5a69"
}

output "admin_applications" {
  value = [for app in data.heist_credential.admin.applications : app.url]
}
