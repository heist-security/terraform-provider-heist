terraform {
  required_providers {
    heist = {
      source = "heist-security/heist"
    }
  }
}

# Reads the access token from HEIST_ACCESS_TOKEN when access_token is unset.
provider "heist" {}
