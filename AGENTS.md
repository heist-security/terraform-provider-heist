# terraform-provider-heist

Public Terraform provider for the Heist external REST API. This repository is
public: never commit credentials, customer data, or details of private Heist
services beyond the published OpenAPI contract.

## Boundaries

- The provider owns Terraform schemas, planning, state, import, replacement,
  destroy behavior and partial-failure recovery. The heist-go SDK owns the REST
  client, request and response types, authentication and errors. Send every API
  request through the pinned SDK; don't hand-write HTTP calls.
- Code must not depend on private Heist packages or repositories.
- Add a resource only when the pinned contract has the endpoints to create,
  read and remove or undo it. A missing operation is an API/SDK prerequisite;
  don't work around it.
- Keep imperative actions (signup, pentests, retests, DNS verification
  checks, reports) out of resources.
- Mark secret inputs `Sensitive`. Reads and imports use safe metadata and never
  reveal secrets.
- Repeated applies must converge without calls that start Heist workflows,
  such as application scope updates.

## Contract

Never edit `api/openapi.json` or `api/openapi.lock.json` by hand. They are
copied from the heist-go tag pinned in `go.mod`; see the README.

## Checks

Run `make check` before handing off. It needs the Terraform CLI on `PATH`.
Tests use the fake API in `internal/provider/fake_api_test.go` and must not
call the live Heist API. Cover new resources there: create, unchanged plan,
update or replacement, import and destroy. Regenerate `docs/` with
`make docs` after schema or example changes.
