package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/heist-security/heist-go/heist"
)

func TestCredentialDataSources(t *testing.T) {
	api := newFakeAPI(t)
	username, roleLevel := "alice", float32(2)
	cred := &fakeCredential{Credential: heist.Credential{
		Id:   "3f6c2a1b-7d4e-4c8a-9b0f-1e2d3c4b5a69",
		Type: heist.CredentialTypeBASIC,
		Applications: []struct {
			EntityId  *string  `json:"entityId"`
			Id        string   `json:"id"`
			IsPrimary bool     `json:"isPrimary"`
			RoleLevel *float32 `json:"roleLevel"`
			Url       string   `json:"url"`
		}{{Id: "0b6f1e2d-3c4b-4a59-8e7d-6c5b4a392817", Url: "https://app.example.com/", IsPrimary: true, RoleLevel: &roleLevel}},
	}, secrets: map[string]string{"password": "secret"}}
	cred.Hint.Username = &username
	api.creds[cred.Id] = cred

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{{
			Config: api.providerConfig() + `
data "heist_credential" "one" {
  id = "3f6c2a1b-7d4e-4c8a-9b0f-1e2d3c4b5a69"
}

data "heist_credentials" "all" {}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("data.heist_credential.one", "type", "BASIC"),
				resource.TestCheckResourceAttr("data.heist_credential.one", "hint.username", "alice"),
				resource.TestCheckResourceAttr("data.heist_credential.one", "applications.#", "1"),
				resource.TestCheckResourceAttr("data.heist_credential.one", "applications.0.url", "https://app.example.com/"),
				resource.TestCheckResourceAttr("data.heist_credential.one", "applications.0.is_primary", "true"),
				resource.TestCheckResourceAttr("data.heist_credential.one", "applications.0.role_level", "2"),
				resource.TestCheckNoResourceAttr("data.heist_credential.one", "applications.0.entity_id"),
				resource.TestCheckResourceAttr("data.heist_credentials.all", "credentials.#", "1"),
				resource.TestCheckResourceAttr("data.heist_credentials.all", "credentials.0.id", cred.Id),
				resource.TestCheckResourceAttr("data.heist_credentials.all", "credentials.0.applications.0.id", "0b6f1e2d-3c4b-4a59-8e7d-6c5b4a392817"),
			),
		}},
	})
}
