terraform {
  required_providers {
    heist = {
      source = "heist-security/heist"
    }
  }
}

# Reads OAuth app credentials from HEIST_CLIENT_ID and HEIST_CLIENT_SECRET, or
# an access token from HEIST_ACCESS_TOKEN, when they are not set here.
provider "heist" {}
