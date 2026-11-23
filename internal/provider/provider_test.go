package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestProvider_missingAccessToken(t *testing.T) {
	t.Setenv("HEIST_ACCESS_TOKEN", "")
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{{
			Config: `
resource "heist_scope_rule" "test" {
  pattern = "app.example.com/**"
  action  = "BLOCK"
}
`,
			ExpectError: regexp.MustCompile(`Missing Heist access token`),
		}},
	})
}
