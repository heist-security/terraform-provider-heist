package provider

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

const appCredentialsName = "heist_application_credentials.test"

// appCredentialsConfig returns a configuration with an application, GOOGLE
// credentials a to d, and the application's tenants, each a list of
// credential names. Changing a credential's login URL in urls replaces it.
// cbd sets create_before_destroy on the credentials.
func appCredentialsConfig(api *fakeAPI, cbd bool, urls map[string]string, tenants ...[]string) string {
	var b strings.Builder
	b.WriteString(api.providerConfig())
	b.WriteString(`
resource "heist_application" "app" {
  url = "https://app.example.com"
}
`)
	for _, name := range []string{"a", "b", "c", "d"} {
		url := "https://app.example.com/login"
		if u, ok := urls[name]; ok {
			url = u
		}
		lifecycle := ""
		if cbd {
			lifecycle = "\n  lifecycle {\n    create_before_destroy = true\n  }\n"
		}
		fmt.Fprintf(&b, `
resource "heist_credential" %q {
  type      = "GOOGLE"
  login_url = %q
%s}
`, name, url, lifecycle)
	}
	if len(tenants) == 0 {
		return b.String()
	}
	b.WriteString(`
resource "heist_application_credentials" "test" {
  application_id = heist_application.app.id
`)
	for _, t := range tenants {
		refs := make([]string, len(t))
		for i, name := range t {
			refs[i] = "heist_credential." + name + ".id"
		}
		fmt.Fprintf(&b, "\n  tenant {\n    credential_ids = [%s]\n  }\n", strings.Join(refs, ", "))
	}
	b.WriteString("}\n")
	return b.String()
}

func TestApplicationCredentialsResource(t *testing.T) {
	api := newFakeAPI(t)
	config := func(tenants ...[]string) string { return appCredentialsConfig(api, false, nil, tenants...) }
	ids := map[string]string{}
	entities := map[string]string{}
	update := resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(appCredentialsName, plancheck.ResourceActionUpdate)}}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: config([]string{"a", "b"}),
				Check: resource.ComposeAggregateTestCheckFunc(
					api.captureIDs(ids),
					api.checkLanes(ids, "a,b"),
					resource.TestCheckResourceAttr(appCredentialsName, "tenant.#", "1"),
					captureEntity(entities, "main", 0),
				),
			},
			{
				// The fake lists credentials in random order.
				Config:           config([]string{"a", "b"}),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()}},
			},
			{
				// Reorder within a lane; b becomes the primary.
				Config:           config([]string{"b", "a"}),
				ConfigPlanChecks: update,
				Check:            resource.ComposeAggregateTestCheckFunc(api.checkLanes(ids, "b,a"), checkEntity(entities, "main", 0)),
			},
			{
				// Add a second tenant.
				Config:           config([]string{"b", "a"}, []string{"c"}),
				ConfigPlanChecks: update,
				Check: resource.ComposeAggregateTestCheckFunc(
					api.checkLanes(ids, "b,a", "c"),
					checkEntity(entities, "main", 0),
					captureEntity(entities, "c", 1),
				),
			},
			{
				// Add a credential.
				Config: config([]string{"b", "a", "d"}, []string{"c"}),
				Check:  api.checkLanes(ids, "b,a,d", "c"),
			},
			{
				// Remove a credential. The credential itself is kept.
				Config: config([]string{"b", "d"}, []string{"c"}),
				Check:  resource.ComposeAggregateTestCheckFunc(api.checkLanes(ids, "b,d", "c"), api.checkCredentialCount(4)),
			},
			{
				// Move a credential between tenants.
				Config: config([]string{"b"}, []string{"c", "d"}),
				Check: resource.ComposeAggregateTestCheckFunc(
					api.checkLanes(ids, "b", "c,d"),
					checkEntity(entities, "main", 0),
					checkEntity(entities, "c", 1),
				),
			},
			{
				// Swap credentials between the main tenant and another. The
				// primary stays in the main tenant.
				Config: config([]string{"d"}, []string{"c", "b"}),
				Check: resource.ComposeAggregateTestCheckFunc(
					api.checkLanes(ids, "d", "c,b"),
					checkEntity(entities, "main", 0),
					checkEntity(entities, "c", 1),
				),
			},
			{
				Config: config([]string{"b"}, []string{"c", "d"}),
				Check:  resource.ComposeAggregateTestCheckFunc(api.checkLanes(ids, "b", "c,d"), checkEntity(entities, "main", 0)),
			},
			{
				// Add a third tenant.
				Config: config([]string{"b"}, []string{"c", "d"}, []string{"a"}),
				Check:  resource.ComposeAggregateTestCheckFunc(api.checkLanes(ids, "b", "c,d", "a"), captureEntity(entities, "a", 2)),
			},
			{
				// Reordering the tenants after the first makes no API calls.
				PreConfig:        api.resetLinkCalls,
				Config:           config([]string{"b"}, []string{"a"}, []string{"c", "d"}),
				ConfigPlanChecks: update,
				Check: resource.ComposeAggregateTestCheckFunc(
					api.checkLinkCalls(0),
					checkEntity(entities, "a", 1),
					checkEntity(entities, "c", 2),
				),
			},
			{
				// Remove a tenant that isn't the last block. a stays in its
				// tenant.
				PreConfig: api.resetLinkCalls,
				Config:    config([]string{"b"}, []string{"a"}),
				Check: resource.ComposeAggregateTestCheckFunc(
					api.checkLanes(ids, "b", "a"),
					checkEntity(entities, "a", 1),
					api.checkLinkCalls(2),
				),
			},
			{
				// A link made outside Terraform shows up as a diff and is
				// removed.
				PreConfig:        func() { api.linkOutside(ids, "c", "a") },
				Config:           config([]string{"b"}, []string{"a"}),
				ConfigPlanChecks: update,
				Check:            api.checkLanes(ids, "b", "a"),
			},
			{
				ResourceName:                         appCredentialsName,
				ImportState:                          true,
				ImportStateVerify:                    true,
				ImportStateIdFunc:                    applicationIDOf,
				ImportStateVerifyIdentifierAttribute: "application_id",
			},
			{
				// Destroy unlinks every credential and keeps them.
				Config: config(),
				Check:  resource.ComposeAggregateTestCheckFunc(api.checkLanes(ids), api.checkCredentialCount(4)),
			},
		},
	})
}

// TestApplicationCredentialsResource_createBeforeDestroy replaces the only
// credential in the main tenant. With create_before_destroy, the new
// credential joins the main tenant before the old one is deleted.
func TestApplicationCredentialsResource_createBeforeDestroy(t *testing.T) {
	api := newFakeAPI(t)
	ids := map[string]string{}
	entities := map[string]string{}
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: appCredentialsConfig(api, true, nil, []string{"a"}, []string{"c"}),
				Check: resource.ComposeAggregateTestCheckFunc(
					api.captureIDs(ids),
					api.checkLanes(ids, "a", "c"),
					captureEntity(entities, "main", 0),
					captureEntity(entities, "c", 1),
				),
			},
			{
				Config: appCredentialsConfig(api, true, map[string]string{"a": "https://app.example.com/new"}, []string{"a"}, []string{"c"}),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("heist_credential.a", plancheck.ResourceActionCreateBeforeDestroy),
					plancheck.ExpectResourceAction(appCredentialsName, plancheck.ResourceActionUpdate),
				}},
				Check: resource.ComposeAggregateTestCheckFunc(
					api.captureIDs(ids),
					api.checkLanes(ids, "a", "c"),
					checkEntity(entities, "main", 0),
					checkEntity(entities, "c", 1),
					api.checkCredentialCount(4),
				),
			},
		},
	})
}

// TestApplicationCredentialsResource_primaryInWrongTenant replaces the only
// credential in the main tenant without create_before_destroy, so deleting it
// moves the primary to the other tenant.
func TestApplicationCredentialsResource_primaryInWrongTenant(t *testing.T) {
	api := newFakeAPI(t)
	ids := map[string]string{}
	// replace_triggered_by forces replacement the same way as
	// terraform apply -replace; changing trigger replaces the resource.
	config := func(trigger int, urls map[string]string) string {
		return strings.Replace(appCredentialsConfig(api, false, urls, []string{"a"}, []string{"c"}),
			"  application_id = heist_application.app.id\n",
			"  application_id = heist_application.app.id\n  lifecycle {\n    replace_triggered_by = [terraform_data.trigger]\n  }\n", 1) +
			fmt.Sprintf("\nresource \"terraform_data\" \"trigger\" {\n  input = %d\n}\n", trigger)
	}
	replaced := map[string]string{"a": "https://app.example.com/new"}
	wantErr := regexp.MustCompile(`terraform apply\s+-replace=heist_application_credentials.<name>`)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: config(1, nil),
				Check:  resource.ComposeAggregateTestCheckFunc(api.captureIDs(ids), api.checkLanes(ids, "a", "c")),
			},
			{
				// Detected on apply, after the credential is deleted.
				Config:      config(1, replaced),
				ExpectError: wantErr,
			},
			{
				// Detected again on the next apply. Plan only warns, so
				// that planning a forced replacement still works.
				Config:      config(1, replaced),
				ExpectError: wantErr,
			},
			{
				// Replacing the resource recovers.
				Config: config(2, replaced),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(appCredentialsName, plancheck.ResourceActionDestroyBeforeCreate),
				}},
				Check: resource.ComposeAggregateTestCheckFunc(api.captureIDs(ids), api.checkLanes(ids, "a", "c")),
			},
		},
	})
}

func TestApplicationCredentialsResource_applicationDeleted(t *testing.T) {
	api := newFakeAPI(t)
	config := appCredentialsConfig(api, false, nil, []string{"a"})
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{
			{Config: config},
			{
				// A 404 for the application removes the resource from state.
				PreConfig: func() {
					api.mu.Lock()
					defer api.mu.Unlock()
					clear(api.apps)
				},
				Config:             config,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestApplicationCredentialsResource_validation(t *testing.T) {
	api := newFakeAPI(t)
	const id = "3f6c2a1b-7d4e-4c8a-9b0f-1e2d3c4b5a69"
	tests := []struct {
		name, tenants, want string
	}{
		{"duplicate credential", fmt.Sprintf("tenant {\n credential_ids = [%q]\n}\ntenant {\n credential_ids = [%[1]q]\n}", id), `Duplicate credential`},
		{"empty tenant", "tenant {\n credential_ids = []\n}", `at least 1`},
		{"no tenants", "", `Invalid Block`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: testProviderFactories(),
				Steps: []resource.TestStep{{
					Config:      api.providerConfig() + fmt.Sprintf("resource \"heist_application_credentials\" \"test\" {\n application_id = %q\n%s\n}\n", id, tt.tenants),
					PlanOnly:    true,
					ExpectError: regexp.MustCompile(tt.want),
				}},
			})
		})
	}
}

func applicationIDOf(s *terraform.State) (string, error) {
	return s.RootModule().Resources[appCredentialsName].Primary.Attributes["application_id"], nil
}

// captureIDs records the IDs of the credentials in state by name.
func (f *fakeAPI) captureIDs(ids map[string]string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		for _, name := range []string{"a", "b", "c", "d"} {
			ids[name] = s.RootModule().Resources["heist_credential."+name].Primary.ID
		}
		ids["app"] = s.RootModule().Resources["heist_application.app"].Primary.ID
		return nil
	}
}

// checkLanes checks the application's lanes in the fake: the main lane,
// whose first credential is the primary, then the other lanes in any order.
// Each lane lists credential names, most privileged first.
func (f *fakeAPI) checkLanes(ids map[string]string, want ...string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		names := map[string]string{}
		for name, id := range ids {
			names[id] = name
		}
		lanes := map[string][]*credentialLink{}
		credential := map[*credentialLink]string{}
		var main string
		for _, l := range f.appLinks(ids["app"]) {
			lanes[*l.EntityId] = append(lanes[*l.EntityId], l)
			for id, c := range f.creds {
				for i := range c.Applications {
					if &c.Applications[i] == l {
						credential[l] = names[id]
					}
				}
			}
			if l.IsPrimary {
				main = *l.EntityId
			}
		}
		var got []string
		for entity, links := range lanes {
			slices.SortFunc(links, func(a, b *credentialLink) int { return cmp.Compare(level(b), level(a)) })
			if entity == main && !links[0].IsPrimary {
				return fmt.Errorf("primary %s is not the most privileged credential of the main lane", credential[links[0]])
			}
			lane := make([]string, len(links))
			for i, l := range links {
				lane[i] = credential[l]
			}
			if entity == main {
				got = append([]string{strings.Join(lane, ",")}, got...)
			} else {
				got = append(got, strings.Join(lane, ","))
			}
		}
		if len(got) > 1 {
			slices.Sort(got[1:])
		}
		sorted := slices.Clone(want)
		if len(sorted) > 1 {
			slices.Sort(sorted[1:])
		}
		if !slices.Equal(got, sorted) {
			return fmt.Errorf("got lanes %q, want %q", got, sorted)
		}
		return nil
	}
}

// linkOutside links a credential into the lane of another, as the dashboard
// would.
func (f *fakeAPI) linkOutside(ids map[string]string, name, laneOf string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var entity string
	for _, l := range f.creds[ids[laneOf]].Applications {
		if l.Id == ids["app"] {
			entity = *l.EntityId
		}
	}
	lvl := float32(-10)
	c := f.creds[ids[name]]
	c.Applications = append(c.Applications, credentialLink{EntityId: &entity, Id: ids["app"], RoleLevel: &lvl, Url: "https://app.example.com/"})
}

func (f *fakeAPI) resetLinkCalls() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.linkCalls = 0
}

func (f *fakeAPI) checkLinkCalls(want int) resource.TestCheckFunc {
	return func(*terraform.State) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.linkCalls != want {
			return fmt.Errorf("got %d link, unlink and reorder calls, want %d", f.linkCalls, want)
		}
		return nil
	}
}

// captureEntity records the entity ID of tenant block i under key.
func captureEntity(entities map[string]string, key string, i int) resource.TestCheckFunc {
	return resource.TestCheckResourceAttrWith(appCredentialsName, fmt.Sprintf("tenant.%d.entity_id", i), func(v string) error {
		if v == "" {
			return fmt.Errorf("tenant %d has no entity_id", i)
		}
		entities[key] = v
		return nil
	})
}

// checkEntity checks that tenant block i has the entity ID recorded under
// key.
func checkEntity(entities map[string]string, key string, i int) resource.TestCheckFunc {
	return resource.TestCheckResourceAttrWith(appCredentialsName, fmt.Sprintf("tenant.%d.entity_id", i), func(v string) error {
		if v != entities[key] {
			return fmt.Errorf("tenant %d entity_id is %s, want %s (%s)", i, v, entities[key], key)
		}
		return nil
	})
}
