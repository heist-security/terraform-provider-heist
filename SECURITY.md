# Security policy

This project is alpha. Security fixes target the default branch and the next
release; there are no backported fixes to earlier tags.

## Private reporting

Do not disclose exploitable vulnerabilities in public issues or pull requests.

Use GitHub's **Security → Report a vulnerability** when private vulnerability
reporting is enabled. If that option is unavailable, contact
**hello@heisthq.com** (the address published at
[heist.security/contact](https://heist.security/contact)) with the subject
"terraform-provider-heist: private security reporting channel" to arrange
confidential disclosure. Do not include passwords, access tokens, customer data
or vulnerability details in that initial email.

Once a private channel is established, include the affected commit or release,
impact, prerequisites and a minimal safe reproduction. This repository covers
the Terraform provider. Do not test the hosted Heist service, other customers'
workspaces or production availability without separate authorization. This
policy does not promise a bounty or response-time SLA.

## Trust boundaries

- The provider's `access_token` is marked sensitive, so Terraform redacts it
  from plan output. It is passed to the heist-go SDK, which sends it only to the
  configured `server_url`. Point `server_url` only at a Heist API you trust.
- Terraform state holds resource IDs and settings, not secrets.
- The Heist service enforces authentication, workspace membership, roles and
  feature restrictions. The provider does not grant or limit access.
- `api/openapi.json` is pinned by SHA-256 in `api/openapi.lock.json`. Builds
  never fetch a schema.
- Dependencies are public Go modules verified by `go.sum`. Documentation and
  vulnerability tools are pinned in a separate `tools/go.mod`.
- Release checksums are signed with the GPG key registered for the
  `heist-security` namespace in the Terraform Registry, and release assets carry
  GitHub build provenance attestations.
