resource "heist_application" "app" {
  url = "https://app.example.com"
}

variable "passwords" {
  type      = map(string)
  sensitive = true
}

# Test accounts in two tenants. create_before_destroy links a replacement
# credential before the old one is deleted, so the main tenant keeps its
# primary credential.
resource "heist_credential" "account" {
  for_each = toset(["acme-admin", "acme-member", "globex-admin"])

  type      = "BASIC"
  login_url = "https://app.example.com/login"

  basic {
    username            = "${each.key}@example.com"
    password_wo         = var.passwords[each.key]
    password_wo_version = 1
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "heist_application_credentials" "app" {
  application_id = heist_application.app.id

  # The main tenant. Its first credential is the primary.
  tenant {
    credential_ids = [
      heist_credential.account["acme-admin"].id,
      heist_credential.account["acme-member"].id,
    ]
  }

  # A separate tenant, for testing access across tenants.
  tenant {
    credential_ids = [heist_credential.account["globex-admin"].id]
  }
}
