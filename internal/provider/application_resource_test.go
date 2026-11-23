package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestApplicationResource(t *testing.T) {
	api := newFakeAPI(t)
	config := func(inScope bool) string {
		return api.providerConfig() + fmt.Sprintf(`
resource "heist_application" "test" {
  url      = "https://app.example.com"
  in_scope = %t
}
`, inScope)
	}
	var id string

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{
			{
				// Create. The API normalizes the URL with a trailing slash;
				// the test framework fails if that leaves a diff.
				Config: config(true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("heist_application.test", "url", "https://app.example.com"),
					resource.TestCheckResourceAttr("heist_application.test", "in_scope", "true"),
					resource.TestCheckResourceAttr("heist_application.test", "main_target", "true"),
					resource.TestCheckResourceAttrWith("heist_application.test", "id", func(v string) error {
						id = v
						return nil
					}),
					api.checkScopeCalls(0),
				),
			},
			{
				// A repeated apply makes no scope calls.
				Config: config(true),
				Check:  api.checkScopeCalls(0),
			},
			{
				// A failed exclusion leaves the change planned for next time.
				PreConfig:   func() { api.setFailScope(true) },
				Config:      config(false),
				ExpectError: regexp.MustCompile(`Unable to update application scope`),
			},
			{
				PreConfig: func() { api.setFailScope(false) },
				Config:    config(false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("heist_application.test", "in_scope", "false"),
					api.checkScopeCalls(1),
				),
			},
			{
				Config: config(true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("heist_application.test", "in_scope", "true"),
					api.checkScopeCalls(2),
				),
			},
			{
				ResourceName:      "heist_application.test",
				ImportState:       true,
				ImportStateVerify: true,
				// Import reads the URL as the API stores it.
				ImportStateVerifyIgnore: []string{"url"},
			},
		},
		CheckDestroy: func(*terraform.State) error {
			api.mu.Lock()
			defer api.mu.Unlock()
			app, ok := api.apps[id]
			if !ok {
				return fmt.Errorf("application %s was deleted; destroy should only exclude it", id)
			}
			if app.InScope {
				return fmt.Errorf("application %s is still in scope after destroy", id)
			}
			return nil
		},
	})
}

func TestApplicationResource_createExcluded(t *testing.T) {
	api := newFakeAPI(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{{
			Config: api.providerConfig() + `
resource "heist_application" "test" {
  url      = "https://app.example.com/path"
  in_scope = false
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("heist_application.test", "in_scope", "false"),
				api.checkScopeCalls(1),
			),
		}},
		// Already excluded, so destroy makes no further scope call.
		CheckDestroy: func(*terraform.State) error { return api.checkScopeCalls(1)(nil) },
	})
}

func TestApplicationResource_removedOutsideTerraform(t *testing.T) {
	api := newFakeAPI(t)
	config := api.providerConfig() + `
resource "heist_application" "test" {
  url = "https://app.example.com"
}
`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{
			{Config: config},
			{
				// A 404 on refresh removes the application from state, so it
				// is planned for creation again.
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

func (f *fakeAPI) setFailScope(fail bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failScope = fail
}

// checkScopeCalls asserts the number of application scope updates, which
// start Heist workflows.
func (f *fakeAPI) checkScopeCalls(want int) resource.TestCheckFunc {
	return func(*terraform.State) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.scopeCalls != want {
			return fmt.Errorf("got %d scope calls, want %d", f.scopeCalls, want)
		}
		return nil
	}
}
