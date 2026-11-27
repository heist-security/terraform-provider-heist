package provider

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

const credentialName = "heist_credential.test"

func TestCredentialResource_basic(t *testing.T) {
	api := newFakeAPI(t)
	config := func(username, password string, version int) string {
		return api.providerConfig() + fmt.Sprintf(`
resource "heist_credential" "test" {
  type      = "BASIC"
  login_url = "https://app.example.com/login"
  basic {
    username            = %q
    password_wo         = %q
    password_wo_version = %d
  }
}
`, username, password, version)
	}
	var id string

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: config("alice", "pw1", 1),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(credentialName, "hint.username", "alice"),
					resource.TestCheckResourceAttr(credentialName, "hint.password_length", "3"),
					resource.TestCheckResourceAttr(credentialName, "accepted_invite", "false"),
					resource.TestCheckNoResourceAttr(credentialName, "basic.password_wo"),
					resource.TestCheckResourceAttrWith(credentialName, "id", func(v string) error {
						id = v
						return nil
					}),
					api.checkCredentialSecret(&id, "password", "pw1"),
					api.checkCredentialCalls(0, 0, 0),
				),
			},
			{
				// A changed write-only value without a new version is
				// not sent.
				Config: config("alice", "ignored", 1),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: api.checkCredentialSecret(&id, "password", "pw1"),
			},
			{
				// A new version sets the password in place.
				Config: config("alice", "password2", 2),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(credentialName, plancheck.ResourceActionUpdate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPtr(credentialName, "id", &id),
					resource.TestCheckResourceAttr(credentialName, "hint.password_length", "9"),
					api.checkCredentialSecret(&id, "password", "password2"),
					api.checkCredentialCalls(0, 1, 0),
				),
			},
			{
				ResourceName:            credentialName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"basic.password_wo_version"},
			},
			{
				// Other changes replace the credential.
				Config: config("bob", "password2", 2),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(credentialName, plancheck.ResourceActionDestroyBeforeCreate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(credentialName, "hint.username", "bob"),
					api.checkCredentialCount(1),
				),
			},
		},
		CheckDestroy: func(*terraform.State) error { return api.checkCredentialCount(0)(nil) },
	})
}

func TestCredentialResource_custom(t *testing.T) {
	api := newFakeAPI(t)
	config := func(email, instructions string, version int, secrets ...string) string {
		var blocks strings.Builder
		for i := 0; i < len(secrets); i += 2 {
			fmt.Fprintf(&blocks, "    secret {\n      name     = %q\n      value_wo = %q\n    }\n", secrets[i], secrets[i+1])
		}
		return api.providerConfig() + fmt.Sprintf(`
resource "heist_credential" "test" {
  type         = "CUSTOM"
  instructions = %q
  custom {
%s    secrets_wo_version = %d
%s  }
}
`, instructions, email, version, blocks.String())
	}
	var id string

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{
			{
				// The email is generated when unset.
				Config: config("", "Sign in with the TOTP.", 1, "PASSWORD", "pw", "TOTP", "seed"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(credentialName, "custom.email", "tester-1@tester.heisthq.com"),
					resource.TestCheckResourceAttr(credentialName, "hint.secret_names.#", "2"),
					resource.TestCheckResourceAttrWith(credentialName, "id", func(v string) error {
						id = v
						return nil
					}),
					api.checkCredentialSecret(&id, "PASSWORD", "pw"),
					api.checkCredentialCalls(1, 0, 0),
				),
			},
			{
				// Repeated applies keep the generated email.
				Config: config("", "Sign in with the TOTP.", 1, "PASSWORD", "pw", "TOTP", "seed"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: api.checkCredentialCalls(1, 0, 0),
			},
			{
				// Edits keep stored secrets and send new ones.
				Config: config("", "Sign in with the PIN.", 1, "PASSWORD", "ignored", "TOTP", "seed", "PIN", "1234"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(credentialName, plancheck.ResourceActionUpdate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPtr(credentialName, "id", &id),
					resource.TestCheckResourceAttr(credentialName, "instructions", "Sign in with the PIN."),
					resource.TestCheckResourceAttr(credentialName, "custom.email", "tester-1@tester.heisthq.com"),
					api.checkCredentialSecret(&id, "PASSWORD", "pw"),
					api.checkCredentialSecret(&id, "PIN", "1234"),
					api.checkCredentialCalls(1, 0, 1),
				),
			},
			{
				// A new version sends every secret value.
				Config: config("", "Sign in with the PIN.", 2, "PASSWORD", "pw2", "TOTP", "seed", "PIN", "1234"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPtr(credentialName, "id", &id),
					api.checkCredentialSecret(&id, "PASSWORD", "pw2"),
					api.checkCredentialCalls(1, 0, 2),
				),
			},
			{
				ResourceName:            credentialName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"custom.secrets_wo_version"},
			},
			{
				// The API keeps the email of an existing CUSTOM credential,
				// so changing it replaces the credential.
				Config: config(`    email = "chosen@tester.heisthq.com"`+"\n", "Sign in with the PIN.", 2, "PASSWORD", "pw2", "TOTP", "seed", "PIN", "1234"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(credentialName, plancheck.ResourceActionDestroyBeforeCreate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(credentialName, "custom.email", "chosen@tester.heisthq.com"),
					api.checkCredentialCount(1),
				),
			},
		},
		CheckDestroy: func(*terraform.State) error { return api.checkCredentialCount(0)(nil) },
	})
}

// TestCredentialResource_importAdoptsUnreadableValues checks that values the
// API never returns don't replace an imported credential.
func TestCredentialResource_importAdoptsUnreadableValues(t *testing.T) {
	api := newFakeAPI(t)
	config := func(headersVersion int) string {
		return api.providerConfig() + fmt.Sprintf(`
resource "heist_credential" "test" {
  type = "API_KEY"
  custom_header {
    name     = "X-Tenant"
    value_wo = "tenant-1"
  }
  custom_headers_wo_version = %d
  api_key {
    api_key_wo         = "key-123"
    header_name        = "Authorization"
    header_prefix      = "Bearer"
    api_key_wo_version = 1
  }
}
`, headersVersion)
	}
	var id string

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: config(1),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(credentialName, "hint.masked_key", "****23"),
					resource.TestCheckResourceAttrWith(credentialName, "id", func(v string) error {
						id = v
						return nil
					}),
					api.checkCredentialSecret(&id, "header:X-Tenant", "tenant-1"),
				),
			},
			{
				// Forget the credential without deleting it, then import it.
				Config: api.providerConfig() + `
removed {
  from = heist_credential.test
  lifecycle {
    destroy = false
  }
}
`,
				Check: api.checkCredentialCount(1),
			},
			{
				Config:             config(1),
				ResourceName:       credentialName,
				ImportState:        true,
				ImportStatePersist: true,
				ImportStateIdFunc:  func(*terraform.State) (string, error) { return id, nil },
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr(credentialName, "api_key.header_prefix"),
					resource.TestCheckResourceAttr(credentialName, "api_key.header_name", "Authorization"),
				),
			},
			{
				// The first apply after import records the configured
				// values without replacing the credential.
				Config: config(1),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(credentialName, plancheck.ResourceActionUpdate)},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPtr(credentialName, "id", &id),
					resource.TestCheckResourceAttr(credentialName, "api_key.header_prefix", "Bearer"),
				),
			},
			{
				// After that, changing an unreadable value replaces it.
				Config: config(2),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(credentialName, plancheck.ResourceActionDestroyBeforeCreate)},
				},
			},
		},
	})
}

// Terraform creates resources concurrently, and the API reserves a generated
// email only when a credential is saved with it.
func TestCredentialResource_generatedEmailsInOneApply(t *testing.T) {
	api := newFakeAPI(t)
	var config strings.Builder
	config.WriteString(api.providerConfig())
	const count = 8
	for i := range count {
		fmt.Fprintf(&config, "resource \"heist_credential\" \"email%d\" {\n  type = \"EMAIL\"\n  email {}\n}\n", i)
	}
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{{
			Config: config.String(),
			Check: func(s *terraform.State) error {
				seen := map[string]string{}
				for i := range count {
					name := fmt.Sprintf("heist_credential.email%d", i)
					email := s.RootModule().Resources[name].Primary.Attributes["email.email"]
					if other, ok := seen[email]; ok {
						return fmt.Errorf("%s and %s both have email %q", other, name, email)
					}
					seen[email] = name
				}
				return nil
			},
		}},
	})
}

func TestCredentialResource_generatedPhoneAndNoPayload(t *testing.T) {
	api := newFakeAPI(t)
	config := api.providerConfig() + `
resource "heist_credential" "sms" {
  type = "SMS"
  sms {}
}

resource "heist_credential" "google" {
  type = "GOOGLE"
}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("heist_credential.sms", "sms.phone", "+15550000001"),
					resource.TestCheckResourceAttr("heist_credential.sms", "sms.phone_prefix", "+1"),
					resource.TestCheckResourceAttr("heist_credential.google", "type", "GOOGLE"),
					api.checkCredentialCalls(1, 0, 0),
				),
			},
			{
				Config:           config,
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}},
				Check:            api.checkCredentialCalls(1, 0, 0),
			},
		},
	})
}

func TestCredentialResource_blocksMatchType(t *testing.T) {
	api := newFakeAPI(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config:      api.providerConfig() + `resource "heist_credential" "test" { type = "BASIC" }`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`A BASIC credential needs a basic block`),
			},
			{
				Config: api.providerConfig() + `
resource "heist_credential" "test" {
  type = "GOOGLE"
  email {}
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`A GOOGLE credential can't have a email block`),
			},
		},
	})
}

func TestCredentialResource_removedOutsideTerraform(t *testing.T) {
	api := newFakeAPI(t)
	config := api.providerConfig() + `
resource "heist_credential" "test" {
  type = "GOOGLE"
}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{
			{Config: config},
			{
				PreConfig: func() {
					api.mu.Lock()
					defer api.mu.Unlock()
					clear(api.creds)
				},
				Config:             config,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// checkCredentialSecret asserts a secret the fake API stored for the
// credential with ID *id.
func (f *fakeAPI) checkCredentialSecret(id *string, key, want string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		c, ok := f.creds[*id]
		if !ok {
			return fmt.Errorf("credential %s not found", *id)
		}
		if got := c.secrets[key]; got != want {
			return fmt.Errorf("secret %s is %q, want %q", key, got, want)
		}
		return nil
	}
}

// checkCredentialCalls asserts the number of generated email or phone
// requests, password updates and CUSTOM edits.
func (f *fakeAPI) checkCredentialCalls(options, password, custom int) resource.TestCheckFunc {
	return func(*terraform.State) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.optionsCalls != options || f.passwordCalls != password || f.customCalls != custom {
			return fmt.Errorf("got %d options, %d password and %d custom calls, want %d, %d and %d",
				f.optionsCalls, f.passwordCalls, f.customCalls, options, password, custom)
		}
		return nil
	}
}

func (f *fakeAPI) checkCredentialCount(want int) resource.TestCheckFunc {
	return func(*terraform.State) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		if len(f.creds) != want {
			return fmt.Errorf("got %d credentials, want %d", len(f.creds), want)
		}
		return nil
	}
}
