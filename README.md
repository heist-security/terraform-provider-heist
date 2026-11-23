# terraform-provider-heist

The Terraform provider for [Heist](https://heist.security). It manages
workspace configuration through the Heist external REST API, using the public
Go SDK in [heist-go](https://github.com/heist-security/heist-go).

| Type | Name | Manages |
| --- | --- | --- |
| Resource | `heist_application` | An application and whether it is in testing scope |
| Resource | `heist_scope_rule` | A URL `ALLOW`/`BLOCK` scope rule |

Reference documentation for each is in [`docs/`](docs/).

## Using the provider

Create an OAuth app in **Settings → OAuth apps** in Heist and export its access
token:

```sh
export HEIST_ACCESS_TOKEN=...
```

```terraform
terraform {
  required_providers {
    heist = {
      source = "heist-security/heist"
    }
  }
}

provider "heist" {}

resource "heist_application" "app" {
  url = "https://app.example.com"
}

resource "heist_scope_rule" "block_admin" {
  pattern = "app.example.com/admin/**"
  action  = "BLOCK"
}
```

Heist retains application history, so destroying a `heist_application`
excludes the application from scope instead of deleting it.

Imperative actions, such as signing up, pentests, retests, DNS verification
checks and report generation, are not Terraform resources. Use the `heist` CLI
from heist-go for those.

## Development

Requires Go (version in `go.mod`), `make`, and the Terraform CLI on `PATH`
(the version CI installs is in `.github/workflows/ci.yml`). No Heist
credentials, private repositories, or network access to Heist are needed.

```sh
make deps    # download modules; the only step that needs the network
make check   # everything CI runs: gofmt, vet, build, tests, docs
make docs    # regenerate docs/ from the schema and examples/
```

After `make deps`, every check works offline, for example with `GOPROXY=off`.
CI runs the checks this way.

Tests run the real Terraform CLI against an in-memory fake of the Heist API in
`internal/provider/fake_api_test.go`. They cover create, read, unchanged plans,
update, import and destroy, and count the API calls that start Heist workflows.

To try a local build in Terraform, add a
[development override](https://developer.hashicorp.com/terraform/cli/config/config-file#development-overrides-for-provider-developers)
for `heist-security/heist` that points at the `dist/` directory `make build`
writes to.

### API contract and SDK

The provider pins a released `github.com/heist-security/heist-go` version in
`go.mod` and sends every API request through its client. `api/openapi.json` is
a byte-for-byte copy of the published contract that SDK release was generated
from. `api/openapi.lock.json` records its version, source URL and SHA-256. A
test checks them against the file and the SDK's `heist.APIVersion`.

To adopt a new SDK release, update `go.mod`, then copy `api/openapi.json` and
`api/openapi.lock.json` from that heist-go tag.

### Releases

Run the **Release** workflow from `main` with a version such as `v0.1.0`. After
a reviewer approves the `release` environment, it signs the checksums, creates
the tag and GitHub release, and the Terraform Registry picks up the new
version. `scripts/build-release.sh` builds the assets.
