resource "heist_application" "app" {
  url = "https://app.example.com"
}

# Add an application without testing it yet.
resource "heist_application" "staging" {
  url      = "https://staging.example.com"
  in_scope = false
}
