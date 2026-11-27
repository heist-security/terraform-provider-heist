# Look up an application Heist discovered by its URL.
data "heist_application" "api" {
  url = "https://api.example.com"
}

output "api" {
  value = {
    id              = data.heist_application.api.id
    in_scope        = data.heist_application.api.in_scope
    requires_review = data.heist_application.api.requires_review
  }
}

# Look up an application by ID.
data "heist_application" "by_id" {
  id = "00000000-0000-4000-8000-000000000000"
}
