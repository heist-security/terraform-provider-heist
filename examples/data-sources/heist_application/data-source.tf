# Look up an application Heist discovered, then block its admin pages.
data "heist_application" "api" {
  url = "https://api.example.com"
}

resource "heist_scope_rule" "block_api_admin" {
  pattern = "${trimsuffix(split("://", data.heist_application.api.url)[1], "/")}/admin/**"
  action  = "BLOCK"
}

# Look up an application by ID.
data "heist_application" "by_id" {
  id = "00000000-0000-4000-8000-000000000000"
}
