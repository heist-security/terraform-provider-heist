# Applications Heist discovered under a main target that need review.
data "heist_application" "app" {
  url = "https://app.example.com"
}

data "heist_applications" "needs_review" {
  parent_application_id = data.heist_application.app.id
  requires_review       = true
}

output "needs_review" {
  value = data.heist_applications.needs_review.applications[*].url
}
