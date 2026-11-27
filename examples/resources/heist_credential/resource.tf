variable "admin_password" {
  type      = string
  sensitive = true
}

variable "totp_seed" {
  type      = string
  sensitive = true
}

# An existing username and password account. Change password_wo_version
# to send a new password.
resource "heist_credential" "admin" {
  type      = "BASIC"
  login_url = "https://app.example.com/login"

  basic {
    username            = "admin@example.com"
    password_wo         = var.admin_password
    password_wo_version = 1
  }
}

# A custom sign-in flow. Heist generates the email address when it is unset.
resource "heist_credential" "sso_user" {
  type         = "CUSTOM"
  login_url    = "https://app.example.com/sso"
  instructions = "Sign in with the email address, then enter the code from the TOTP secret."

  custom {
    secrets_wo_version = 1

    secret {
      name     = "TOTP"
      value_wo = var.totp_seed
    }
  }
}
