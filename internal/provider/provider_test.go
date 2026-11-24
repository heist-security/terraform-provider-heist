package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

const scopeRuleConfig = `
resource "heist_scope_rule" "test" {
  pattern = "app.example.com/**"
  action  = "BLOCK"
}
`

func TestProvider_missingAccessToken(t *testing.T) {
	clearCredentialEnv(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{{
			Config:      scopeRuleConfig,
			ExpectError: regexp.MustCompile(`Missing Heist credentials`),
		}},
	})
}

func TestProvider_credentialValidation(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		env      map[string]string
		want     string
	}{
		{
			name:     "token and client credentials",
			provider: `access_token = "token"` + "\n" + `client_id = "id"` + "\n" + `client_secret = "secret"`,
			want:     `Conflicting Heist credentials`,
		},
		{
			name: "token and client credentials in environment",
			env:  map[string]string{"HEIST_ACCESS_TOKEN": "token", "HEIST_CLIENT_ID": "id", "HEIST_CLIENT_SECRET": "secret"},
			want: `Conflicting Heist credentials`,
		},
		{
			name:     "client ID only",
			provider: `client_id = "id"`,
			want:     `Incomplete Heist client credentials`,
		},
		{
			name: "client secret only",
			env:  map[string]string{"HEIST_CLIENT_SECRET": "secret"},
			want: `Incomplete Heist client credentials`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearCredentialEnv(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: testProviderFactories(),
				Steps: []resource.TestStep{{
					Config:      fmt.Sprintf("provider \"heist\" {\n%s\n}\n", tt.provider) + scopeRuleConfig,
					ExpectError: regexp.MustCompile(tt.want),
				}},
			})
		})
	}
}

// TestProvider_configCredentialsTakePrecedence sets wrong credentials of the
// other kind in the environment, so the apply succeeds only if the provider
// ignores them in favour of the credentials in its configuration.
func TestProvider_configCredentialsTakePrecedence(t *testing.T) {
	tests := []struct {
		name   string
		config func(*fakeAPI) string
		env    map[string]string
	}{
		{
			name:   "access token in config",
			config: (*fakeAPI).providerConfig,
			env:    map[string]string{"HEIST_CLIENT_ID": "wrong-id", "HEIST_CLIENT_SECRET": "wrong-secret"},
		},
		{
			name: "client ID in config, secret in environment",
			config: func(f *fakeAPI) string {
				return fmt.Sprintf(`
provider "heist" {
  server_url = %q
  token_url  = %q
  client_id  = %q
}
`, f.url, f.url+"/oauth2/token", testClientID)
			},
			env: map[string]string{"HEIST_CLIENT_SECRET": testClientSecret, "HEIST_ACCESS_TOKEN": "wrong-token"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := newFakeAPI(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: testProviderFactories(),
				Steps:                    []resource.TestStep{{Config: tt.config(api) + scopeRuleConfig, Check: api.checkRuleCount(1)}},
				CheckDestroy:             api.checkRuleCount(0),
			})
		})
	}
}

// TestProvider_clientCredentials applies two resources with tokens that the
// fake API accepts only once, so the apply succeeds only if the provider
// exchanges the client credentials and refreshes the token.
func TestProvider_clientCredentials(t *testing.T) {
	api := newFakeAPI(t)
	config := api.clientCredentialsConfig() + `
resource "heist_scope_rule" "a" {
  pattern = "app.example.com/a/**"
  action  = "BLOCK"
}

resource "heist_scope_rule" "b" {
  pattern = "app.example.com/b/**"
  action  = "BLOCK"
}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{{
			Config: config,
			Check: resource.ComposeAggregateTestCheckFunc(
				api.checkRuleCount(2),
				func(*terraform.State) error {
					api.mu.Lock()
					defer api.mu.Unlock()
					if api.exchanges < 2 {
						return fmt.Errorf("got %d token exchanges, want at least 2", api.exchanges)
					}
					return nil
				},
			),
		}},
		CheckDestroy: api.checkRuleCount(0),
	})
}

func TestProvider_clientCredentialsFromEnvironment(t *testing.T) {
	api := newFakeAPI(t)
	t.Setenv("HEIST_SERVER_URL", api.url)
	t.Setenv("HEIST_TOKEN_URL", api.url+"/oauth2/token")
	t.Setenv("HEIST_CLIENT_ID", testClientID)
	t.Setenv("HEIST_CLIENT_SECRET", testClientSecret)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps:                    []resource.TestStep{{Config: scopeRuleConfig, Check: api.checkRuleCount(1)}},
		CheckDestroy:             api.checkRuleCount(0),
	})
}

func TestProvider_invalidClientCredentials(t *testing.T) {
	api := newFakeAPI(t)
	t.Setenv("HEIST_SERVER_URL", api.url)
	t.Setenv("HEIST_TOKEN_URL", api.url+"/oauth2/token")
	t.Setenv("HEIST_CLIENT_ID", testClientID)
	t.Setenv("HEIST_CLIENT_SECRET", "wrong-secret")
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{{
			Config:      scopeRuleConfig,
			ExpectError: regexp.MustCompile(`token endpoint`),
		}},
	})
}
