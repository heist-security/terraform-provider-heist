package provider

import (
	"context"
	"errors"
	"fmt"
	"iter"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/heist-security/heist-go/heist"
)

// errMissingBody reports a 2xx response the SDK could not decode into its
// success type, for example one with a non-JSON content type.
var errMissingBody = errors.New("heist: response did not include the expected JSON body")

// clientFrom returns the SDK client passed from provider Configure. It returns
// nil without diagnostics before the provider is configured, which Terraform
// does when validating configuration.
func clientFrom(providerData any, diags *diag.Diagnostics) *heist.ClientWithResponses {
	if providerData == nil {
		return nil
	}
	client, ok := providerData.(*heist.ClientWithResponses)
	if !ok {
		diags.AddError("Unexpected provider data", fmt.Sprintf("Expected *heist.ClientWithResponses, got %T.", providerData))
		return nil
	}
	return client
}

// parseID parses a Heist object ID, adding a diagnostic when it is not a UUID.
func parseID(id string, diags *diag.Diagnostics) (uuid.UUID, bool) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		diags.AddError("Invalid Heist ID", fmt.Sprintf("%q is not a UUID: %s", id, err))
		return uuid.UUID{}, false
	}
	return parsed, true
}

// allApplications yields every application matching params once, in the
// largest pages the API returns. The list is paged by offset, so an
// application added while paging can repeat the last one of a page.
func allApplications(ctx context.Context, client *heist.ClientWithResponses, params heist.ListApplicationsParams) iter.Seq2[heist.Application, error] {
	return func(yield func(heist.Application, error) bool) {
		size := 100
		params.Size = &size
		seen := map[string]bool{}
		for app, err := range client.AllApplications(ctx, params) {
			if err == nil && seen[app.Id] {
				continue
			}
			seen[app.Id] = true
			if !yield(app, err) {
				return
			}
		}
	}
}
