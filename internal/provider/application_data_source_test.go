package provider

import (
	"encoding/json"
	"fmt"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/heist-security/heist-go/heist"
)

func TestApplicationDataSource(t *testing.T) {
	api := newFakeAPI(t)
	root := api.addApplication(heist.Application{
		Url:         "https://app.example.com/",
		MainTarget:  true,
		InScope:     true,
		Environment: new("production"),
	})
	// The SDK models the repository as an anonymous struct, so set it from JSON.
	if err := json.Unmarshal([]byte(`{"gitRepository": {"provider": "github", "owner": "acme", "name": "web"}}`), root); err != nil {
		t.Fatal(err)
	}
	child := api.addApplication(heist.Application{
		Url:                  "https://api.app.example.com/",
		RequiresReview:       true,
		MissingAuth:          true,
		ParentApplicationIds: []string{root.Id},
	})

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{{
			Config: api.providerConfig() + fmt.Sprintf(`
data "heist_application" "by_id" {
  id = %q
}

# Matches https://app.example.com/ as Heist stores it.
data "heist_application" "by_url" {
  url = "HTTPS://app.example.com"
}
`, child.Id),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("data.heist_application.by_id", "url", child.Url),
				resource.TestCheckResourceAttr("data.heist_application.by_id", "in_scope", "false"),
				resource.TestCheckResourceAttr("data.heist_application.by_id", "main_target", "false"),
				resource.TestCheckResourceAttr("data.heist_application.by_id", "created_at", child.CreatedAt),
				resource.TestCheckResourceAttr("data.heist_application.by_id", "domain", "example.com"),
				resource.TestCheckResourceAttr("data.heist_application.by_id", "requires_review", "true"),
				resource.TestCheckResourceAttr("data.heist_application.by_id", "missing_auth", "true"),
				resource.TestCheckNoResourceAttr("data.heist_application.by_id", "environment"),
				resource.TestCheckResourceAttr("data.heist_application.by_id", "parent_application_ids.#", "1"),
				resource.TestCheckResourceAttr("data.heist_application.by_id", "parent_application_ids.0", root.Id),
				resource.TestCheckNoResourceAttr("data.heist_application.by_id", "git_repository.%"),

				resource.TestCheckResourceAttr("data.heist_application.by_url", "id", root.Id),
				resource.TestCheckResourceAttr("data.heist_application.by_url", "url", "HTTPS://app.example.com"),
				resource.TestCheckResourceAttr("data.heist_application.by_url", "main_target", "true"),
				resource.TestCheckResourceAttr("data.heist_application.by_url", "environment", "production"),
				resource.TestCheckResourceAttr("data.heist_application.by_url", "parent_application_ids.#", "0"),
				resource.TestCheckResourceAttr("data.heist_application.by_url", "git_repository.provider", "github"),
				resource.TestCheckResourceAttr("data.heist_application.by_url", "git_repository.owner", "acme"),
				resource.TestCheckResourceAttr("data.heist_application.by_url", "git_repository.name", "web"),
				resource.TestCheckNoResourceAttr("data.heist_application.by_url", "git_repository.project"),
				api.checkScopeCalls(0),
			),
		}},
	})
}

func TestApplicationDataSource_lookupErrors(t *testing.T) {
	api := newFakeAPI(t)
	api.addApplication(heist.Application{Url: "https://dup.example.com"})
	api.addApplication(heist.Application{Url: "https://dup.example.com/"})
	config := func(args string) string {
		return api.providerConfig() + fmt.Sprintf("data \"heist_application\" \"test\" {\n%s\n}\n", args)
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config:      config(`url = "https://missing.example.com"`),
				ExpectError: regexp.MustCompile(`No application has URL "https://missing.example.com"`),
			},
			{
				Config:      config(`url = "https://dup.example.com"`),
				ExpectError: regexp.MustCompile(`2 applications match URL "https://dup.example.com"`),
			},
			{
				Config:      config(fmt.Sprintf("id = %q", uuid.NewString())),
				ExpectError: regexp.MustCompile(`Application not found`),
			},
			{
				Config:      config(`id = "not-a-uuid"`),
				ExpectError: regexp.MustCompile(`Invalid Heist ID`),
			},
			{
				Config:      config(fmt.Sprintf("id = %q\nurl = \"https://dup.example.com\"", uuid.NewString())),
				ExpectError: regexp.MustCompile(`Invalid Attribute Combination`),
			},
			{
				Config:      config(""),
				ExpectError: regexp.MustCompile(`Missing Attribute Configuration`),
			},
		},
	})
}

func TestApplicationsDataSource(t *testing.T) {
	api := newFakeAPI(t)
	root := api.addApplication(heist.Application{Url: "https://app.example.com/", InScope: true, MainTarget: true})
	// More children than fit on one 100-item page.
	for i := range 105 {
		api.addApplication(heist.Application{
			Url:                  fmt.Sprintf("https://sub%03d.app.example.com/", i),
			InScope:              true,
			ParentApplicationIds: []string{root.Id},
		})
	}
	excluded := api.addApplication(heist.Application{Url: "https://old.app.example.com/", ParentApplicationIds: []string{root.Id}})
	review := api.addApplication(heist.Application{Url: "https://other.example.com/", InScope: true, RequiresReview: true})

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories(),
		Steps: []resource.TestStep{{
			Config: api.providerConfig() + fmt.Sprintf(`
data "heist_applications" "all" {}

data "heist_applications" "children" {
  parent_application_id = %q
  in_scope              = true
}

data "heist_applications" "excluded" {
  in_scope = false
}

data "heist_applications" "roots" {
  root_only = true
}

data "heist_applications" "review" {
  requires_review = true
}

data "heist_applications" "search" {
  search = "OTHER"
}

data "heist_applications" "none" {
  search = "nothing"
}
`, root.Id),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("data.heist_applications.all", "applications.#", "108"),
				resource.TestCheckResourceAttr("data.heist_applications.children", "applications.#", "105"),
				resource.TestCheckResourceAttr("data.heist_applications.excluded", "applications.#", "1"),
				resource.TestCheckResourceAttr("data.heist_applications.excluded", "applications.0.id", excluded.Id),
				resource.TestCheckResourceAttr("data.heist_applications.roots", "applications.#", "2"),
				resource.TestCheckResourceAttr("data.heist_applications.roots", "applications.0.id", root.Id),
				resource.TestCheckResourceAttr("data.heist_applications.roots", "applications.1.id", review.Id),
				resource.TestCheckResourceAttr("data.heist_applications.review", "applications.#", "1"),
				resource.TestCheckResourceAttr("data.heist_applications.review", "applications.0.url", review.Url),
				resource.TestCheckResourceAttr("data.heist_applications.review", "applications.0.requires_review", "true"),
				resource.TestCheckResourceAttr("data.heist_applications.review", "applications.0.domain", "example.com"),
				resource.TestCheckResourceAttr("data.heist_applications.search", "applications.#", "1"),
				resource.TestCheckResourceAttr("data.heist_applications.search", "applications.0.id", review.Id),
				resource.TestCheckResourceAttr("data.heist_applications.none", "applications.#", "0"),
				api.checkScopeCalls(0),
			),
		}},
	})
}

// addApplication seeds an application, filling in the ID, creation time,
// domain and parent list when they are unset.
func (f *fakeAPI) addApplication(app heist.Application) *heist.Application {
	f.mu.Lock()
	defer f.mu.Unlock()
	if app.Id == "" {
		app.Id = uuid.NewString()
	}
	if app.CreatedAt == "" {
		app.CreatedAt = "2026-11-23T00:00:00Z"
	}
	if app.Domain == "" {
		app.Domain = "example.com"
	}
	if app.ParentApplicationIds == nil {
		app.ParentApplicationIds = []string{}
	}
	f.apps[app.Id] = &app
	return &app
}
