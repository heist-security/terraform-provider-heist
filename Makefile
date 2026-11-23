.PHONY: check check-go check-docs build docs deps vulncheck

# Run every offline check CI runs. CI also runs vulncheck.
check: check-go check-docs

# Download provider and tool modules. Apart from installing the Terraform CLI
# that tests run, this is the only step that needs the network.
deps:
	go mod download
	cd tools && go mod download

# Format, vet, build and test. Tests run the Terraform CLI against an
# in-memory fake of the Heist API; they never call the live API.
check-go: build
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test ./...

# Fail if docs/ is stale relative to the provider schema and examples/.
check-docs: docs
	git diff --exit-code -- docs
	test -z "$$(git ls-files --others --exclude-standard -- docs)"

build:
	go build -o dist/terraform-provider-heist .

# Generate docs/ from the provider schema and examples/.
docs:
	go tool -modfile=tools/go.mod tfplugindocs generate --provider-name heist

# Report known vulnerabilities in reachable code. Queries vuln.go.dev, so it
# needs network access and is not part of the offline check target.
vulncheck:
	go tool -modfile=tools/go.mod govulncheck ./...
