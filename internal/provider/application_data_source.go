package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/datasourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/heist-security/heist-go/heist"
)

var (
	_ datasource.DataSourceWithConfigure        = (*applicationDataSource)(nil)
	_ datasource.DataSourceWithConfigValidators = (*applicationDataSource)(nil)
)

func newApplicationDataSource() datasource.DataSource {
	return &applicationDataSource{}
}

type applicationDataSource struct {
	client *heist.ClientWithResponses
}

// applicationDataModel is an application as the data sources expose it.
type applicationDataModel struct {
	ID                   types.String        `tfsdk:"id"`
	URL                  types.String        `tfsdk:"url"`
	InScope              types.Bool          `tfsdk:"in_scope"`
	MainTarget           types.Bool          `tfsdk:"main_target"`
	CreatedAt            types.String        `tfsdk:"created_at"`
	Domain               types.String        `tfsdk:"domain"`
	RequiresReview       types.Bool          `tfsdk:"requires_review"`
	MissingAuth          types.Bool          `tfsdk:"missing_auth"`
	Environment          types.String        `tfsdk:"environment"`
	ParentApplicationIDs []string            `tfsdk:"parent_application_ids"`
	GitRepository        *gitRepositoryModel `tfsdk:"git_repository"`
}

type gitRepositoryModel struct {
	Provider types.String `tfsdk:"provider"`
	Owner    types.String `tfsdk:"owner"`
	Project  types.String `tfsdk:"project"`
	Name     types.String `tfsdk:"name"`
}

func (d *applicationDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_application"
}

func (d *applicationDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	attrs := applicationAttributes()
	attrs["id"] = schema.StringAttribute{
		Description: "Application ID to look up. Exactly one of `id` and `url` is required.",
		Optional:    true,
		Computed:    true,
	}
	attrs["url"] = schema.StringAttribute{
		Description: "Application URL to look up. Exactly one of `id` and `url` is required. Matching ignores " +
			"scheme and host case and a trailing slash, and fails unless exactly one application matches.",
		Optional: true,
		Computed: true,
	}
	resp.Schema = schema.Schema{
		Description: "Looks up one application by ID or URL, including applications Heist discovered and ones " +
			"created outside Terraform.",
		Attributes: attrs,
	}
}

func (d *applicationDataSource) ConfigValidators(context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{
		datasourcevalidator.ExactlyOneOf(path.MatchRoot("id"), path.MatchRoot("url")),
	}
}

func (d *applicationDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = clientFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *applicationDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config applicationDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state applicationDataModel
	if !config.ID.IsNull() {
		id, ok := parseID(config.ID.ValueString(), &resp.Diagnostics)
		if !ok {
			return
		}
		res, err := d.client.GetApplicationWithResponse(ctx, id)
		if heist.IsNotFound(err) {
			resp.Diagnostics.AddError("Application not found", fmt.Sprintf("No application has ID %s.", id))
			return
		}
		if err == nil && res.JSON200 == nil {
			err = errMissingBody
		}
		if err != nil {
			resp.Diagnostics.AddError("Unable to read application", err.Error())
			return
		}
		state = applicationDetailData(*res.JSON200)
	} else {
		app, ok := d.findByURL(ctx, config.URL.ValueString(), &resp.Diagnostics)
		if !ok {
			return
		}
		state = applicationData(app)
		// Keep the configured URL rather than the API's normalized form.
		state.URL = config.URL
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// findByURL lists every application and returns the only one whose URL
// matches. The list endpoint's search filter does not define how it matches,
// so this compares URLs itself.
func (d *applicationDataSource) findByURL(ctx context.Context, appURL string, diags *diag.Diagnostics) (heist.Application, bool) {
	var matches []heist.Application
	for app, err := range d.client.AllApplications(ctx, heist.ListApplicationsParams{Size: &maxPageSize}) {
		if err != nil {
			diags.AddError("Unable to list applications", err.Error())
			return heist.Application{}, false
		}
		if sameURL(appURL, app.Url) {
			matches = append(matches, app)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], true
	case 0:
		diags.AddError("Application not found", fmt.Sprintf("No application has URL %q.", appURL))
	default:
		ids := make([]string, len(matches))
		for i, app := range matches {
			ids[i] = app.Id
		}
		diags.AddError("Several applications match",
			fmt.Sprintf("%d applications match URL %q: %s. Look the application up by id instead.",
				len(matches), appURL, strings.Join(ids, ", ")))
	}
	return heist.Application{}, false
}

// applicationAttributes returns the computed attributes of an application in
// the data sources.
func applicationAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id":          schema.StringAttribute{Description: "Application ID.", Computed: true},
		"url":         schema.StringAttribute{Description: "Application URL.", Computed: true},
		"in_scope":    schema.BoolAttribute{Description: "Whether Heist tests the application.", Computed: true},
		"main_target": schema.BoolAttribute{Description: "Whether the application is a main target rather than one discovered by Heist.", Computed: true},
		"created_at":  schema.StringAttribute{Description: "When the application was created.", Computed: true},
		"domain": schema.StringAttribute{
			Description: "Workspace domain the application belongs to, for example `example.com` for `app.example.com`.",
			Computed:    true,
		},
		"requires_review": schema.BoolAttribute{Description: "Whether the application needs review in Heist.", Computed: true},
		"missing_auth":    schema.BoolAttribute{Description: "Whether the application needs authentication Heist does not have.", Computed: true},
		"environment":     schema.StringAttribute{Description: "Environment of the application, or null when unset.", Computed: true},
		"parent_application_ids": schema.ListAttribute{
			Description: "IDs of the applications this one was discovered under. Empty for root applications.",
			ElementType: types.StringType,
			Computed:    true,
		},
		"git_repository": schema.SingleNestedAttribute{
			Description: "Git repository attached to the application, or null when none is.",
			Computed:    true,
			Attributes: map[string]schema.Attribute{
				"provider": schema.StringAttribute{Description: "Git hosting provider.", Computed: true},
				"owner":    schema.StringAttribute{Description: "Repository owner or organization.", Computed: true},
				"project":  schema.StringAttribute{Description: "Project containing the repository, or null when the provider has none.", Computed: true},
				"name":     schema.StringAttribute{Description: "Repository name.", Computed: true},
			},
		},
	}
}

func applicationData(app heist.Application) applicationDataModel {
	m := applicationDataModel{
		ID:                   types.StringValue(app.Id),
		URL:                  types.StringValue(app.Url),
		InScope:              types.BoolValue(app.InScope),
		MainTarget:           types.BoolValue(app.MainTarget),
		CreatedAt:            types.StringValue(app.CreatedAt),
		Domain:               types.StringValue(app.Domain),
		RequiresReview:       types.BoolValue(app.RequiresReview),
		MissingAuth:          types.BoolValue(app.MissingAuth),
		Environment:          types.StringPointerValue(app.Environment),
		ParentApplicationIDs: nonNil(app.ParentApplicationIds),
	}
	if r := app.GitRepository; r != nil {
		m.GitRepository = gitRepository(string(r.Provider), r.Owner, r.Project, r.Name)
	}
	return m
}

// applicationDetailData is applicationData for the GetApplication response,
// which the SDK models as a separate type.
func applicationDetailData(app heist.ApplicationDetail) applicationDataModel {
	m := applicationDataModel{
		ID:                   types.StringValue(app.Id),
		URL:                  types.StringValue(app.Url),
		InScope:              types.BoolValue(app.InScope),
		MainTarget:           types.BoolValue(app.MainTarget),
		CreatedAt:            types.StringValue(app.CreatedAt),
		Domain:               types.StringValue(app.Domain),
		RequiresReview:       types.BoolValue(app.RequiresReview),
		MissingAuth:          types.BoolValue(app.MissingAuth),
		Environment:          types.StringPointerValue(app.Environment),
		ParentApplicationIDs: nonNil(app.ParentApplicationIds),
	}
	if r := app.GitRepository; r != nil {
		m.GitRepository = gitRepository(string(r.Provider), r.Owner, r.Project, r.Name)
	}
	return m
}

func gitRepository(provider, owner string, project *string, name string) *gitRepositoryModel {
	return &gitRepositoryModel{
		Provider: types.StringValue(provider),
		Owner:    types.StringValue(owner),
		Project:  types.StringPointerValue(project),
		Name:     types.StringValue(name),
	}
}

// nonNil returns an empty list for a missing one, so the attribute is never null.
func nonNil(ids []string) []string {
	if ids == nil {
		return []string{}
	}
	return ids
}
