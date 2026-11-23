# Contributing

Please open an issue for substantial changes before implementation. Use the
private channel in SECURITY.md for security vulnerabilities.

## Development

Use the Go version in `go.mod`, install the Terraform CLI, and run `make deps`
to download modules. After that, every check works offline and needs no Heist
credentials or private repository access.

Before a pull request:

    make check

`make check` runs the same checks as CI; see the `Makefile` for each target.

Tests drive the Terraform CLI against the in-memory fake API in
`internal/provider/fake_api_test.go` and must not call the live Heist API.
Never commit access tokens, `.env` files, Terraform state or real customer
data.

## Provider and SDK boundaries

The provider owns Terraform state and resource lifecycle. The REST client,
request and response types, authentication and error handling belong in
[heist-go](https://github.com/heist-security/heist-go). Send every API request
through the SDK.

Add a resource only when the contract has the operations to create, read and
remove or undo it. Imperative actions, such as pentests, retests, DNS
verification checks and reports, are not resources.

## Compatibility

Users' configurations and state depend on the provider schema. Prefer additive
changes. Renaming or removing a resource or attribute, changing its type, or
changing what apply, import or destroy does to existing resources is a breaking
change. While releases are `v0.x`, it needs a new minor version and a note in
the release.

## API contract updates

`api/openapi.json` is a byte-for-byte copy of the published, immutable contract
that the pinned heist-go release targets. Never edit it or
`api/openapi.lock.json` by hand. To adopt a new SDK release, follow
[API contract and SDK](README.md#api-contract-and-sdk) in the README; a test
fails if the snapshot and SDK versions disagree.

Contract changes themselves, such as new endpoints or fields, are made in the
Heist service, published, and released in heist-go before the provider can use
them.

## Code

Original code contributions are provided under the MIT license. Keep
third-party notices intact. The license grants no rights to Heist names or
logos.
