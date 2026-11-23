package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestScopeRuleResource(t *testing.T) {
	api := newFakeAPI(t)
	config := func(action string) string {
		return api.providerConfig() + fmt.Sprintf(`
resource "heist_scope_rule" "test" {
  pattern = "app.example.com/admin/**"
  action  = %q
}
`, action)
	}
	var firstID string

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: config("BLOCK"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("heist_scope_rule.test", "pattern", "app.example.com/admin/**"),
					resource.TestCheckResourceAttr("heist_scope_rule.test", "action", "BLOCK"),
					resource.TestCheckResourceAttrSet("heist_scope_rule.test", "created_at"),
					resource.TestCheckResourceAttrWith("heist_scope_rule.test", "id", func(v string) error {
						firstID = v
						return nil
					}),
				),
			},
			{
				// Changing the action replaces the rule.
				Config: config("ALLOW"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("heist_scope_rule.test", "action", "ALLOW"),
					resource.TestCheckResourceAttrWith("heist_scope_rule.test", "id", func(v string) error {
						if v == firstID {
							return fmt.Errorf("rule was not replaced")
						}
						return nil
					}),
					api.checkRuleCount(1),
				),
			},
			{
				ResourceName:      "heist_scope_rule.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
		CheckDestroy: api.checkRuleCount(0),
	})
}

func TestScopeRuleResource_invalidAction(t *testing.T) {
	api := newFakeAPI(t)
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{{
			Config: api.providerConfig() + `
resource "heist_scope_rule" "test" {
  pattern = "app.example.com/**"
  action  = "MAYBE"
}
`,
			PlanOnly:    true,
			ExpectError: regexp.MustCompile(`value must be one of`),
		}},
	})
}

func (f *fakeAPI) checkRuleCount(want int) resource.TestCheckFunc {
	return func(*terraform.State) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		if len(f.rules) != want {
			return fmt.Errorf("got %d scope rules, want %d", len(f.rules), want)
		}
		return nil
	}
}
