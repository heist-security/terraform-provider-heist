package provider

import (
	"errors"
	"fmt"

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

// maxPageSize is the largest page the API's list operations return.
var maxPageSize = 100
