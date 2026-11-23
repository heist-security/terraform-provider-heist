package provider

import (
	"context"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/heist-security/heist-go/heist"
)

var (
	_ resource.ResourceWithConfigure   = (*applicationResource)(nil)
	_ resource.ResourceWithImportState = (*applicationResource)(nil)
)

func newApplicationResource() resource.Resource {
	return &applicationResource{}
}

type applicationResource struct {
	client *heist.ClientWithResponses
}

type applicationModel struct {
	ID         types.String `tfsdk:"id"`
	URL        types.String `tfsdk:"url"`
	InScope    types.Bool   `tfsdk:"in_scope"`
	MainTarget types.Bool   `tfsdk:"main_target"`
	CreatedAt  types.String `tfsdk:"created_at"`
}

func (r *applicationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_application"
}

func (r *applicationResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "An application in Heist's testing scope. Creating one adds the URL as an in-scope main target. " +
			"Heist retains application history, so destroying this resource excludes the application from scope " +
			"instead of deleting it. Import an existing or discovered application by ID to manage its scope.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description:   "Application ID.",
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"url": schema.StringAttribute{
				Description:   "Application URL. Changing it replaces the application.",
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"in_scope": schema.BoolAttribute{
				Description: "Whether Heist tests the application. Including an application starts post-discovery " +
					"processing; excluding it preserves its history. Defaults to `true`.",
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(true),
			},
			"main_target": schema.BoolAttribute{
				Description:   "Whether the application is a main target rather than one discovered by Heist.",
				Computed:      true,
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
			},
			"created_at": schema.StringAttribute{
				Description:   "When the application was created.",
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *applicationResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFrom(req.ProviderData, &resp.Diagnostics)
}

func (r *applicationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan applicationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	res, err := r.client.CreateApplicationWithResponse(ctx, heist.CreateApplicationJSONRequestBody{Url: plan.URL.ValueString()})
	if err == nil && res.JSON201 == nil {
		err = errMissingBody
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to create application", err.Error())
		return
	}
	app := res.JSON201.Application
	// Keep the configured URL; Read only replaces it on a meaningful change.
	state := applicationState(app, plan.URL)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
	if resp.Diagnostics.HasError() || app.InScope == plan.InScope.ValueBool() {
		return
	}

	// The application exists, so saved state lets a later apply retry the
	// scope change. Terraform taints the resource when this step fails.
	id, ok := parseID(app.Id, &resp.Diagnostics)
	if !ok {
		return
	}
	updated, diags := r.setScope(ctx, id, plan.InScope.ValueBool())
	resp.Diagnostics.Append(diags...)
	if updated != nil {
		resp.Diagnostics.Append(resp.State.Set(ctx, applicationState(*updated, plan.URL))...)
	}
}

func (r *applicationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state applicationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id, ok := parseID(state.ID.ValueString(), &resp.Diagnostics)
	if !ok {
		return
	}

	res, err := r.client.GetApplicationWithResponse(ctx, id)
	if heist.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err == nil && res.JSON200 == nil {
		err = errMissingBody
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read application", err.Error())
		return
	}
	app := res.JSON200
	state.InScope = types.BoolValue(app.InScope)
	state.MainTarget = types.BoolValue(app.MainTarget)
	state.CreatedAt = types.StringValue(app.CreatedAt)
	if !sameURL(state.URL.ValueString(), app.Url) {
		state.URL = types.StringValue(app.Url)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *applicationResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state applicationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// in_scope is the only attribute updated in place, so it has changed.
	id, ok := parseID(state.ID.ValueString(), &resp.Diagnostics)
	if !ok {
		return
	}
	app, diags := r.setScope(ctx, id, plan.InScope.ValueBool())
	resp.Diagnostics.Append(diags...)
	if app == nil {
		// Keep the prior state so the failed change is planned again.
		resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, applicationState(*app, plan.URL))...)
}

func (r *applicationResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state applicationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() || !state.InScope.ValueBool() {
		return
	}
	id, ok := parseID(state.ID.ValueString(), &resp.Diagnostics)
	if !ok {
		return
	}
	_, diags := r.setScope(ctx, id, false)
	resp.Diagnostics.Append(diags...)
}

func (r *applicationResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// setScope includes or excludes an application. A 404 when excluding means the
// application is already gone, which is not an error.
func (r *applicationResource) setScope(ctx context.Context, id uuid.UUID, inScope bool) (*heist.Application, diag.Diagnostics) {
	var diags diag.Diagnostics
	res, err := r.client.UpdateApplicationScopeWithResponse(ctx, id, heist.UpdateApplicationScopeJSONRequestBody{InScope: inScope})
	if !inScope && heist.IsNotFound(err) {
		return nil, diags
	}
	if err == nil && res.JSON200 == nil {
		err = errMissingBody
	}
	if err != nil {
		diags.AddError("Unable to update application scope", err.Error())
		return nil, diags
	}
	return &res.JSON200.Application, diags
}

func applicationState(app heist.Application, configuredURL types.String) applicationModel {
	return applicationModel{
		ID:         types.StringValue(app.Id),
		URL:        configuredURL,
		InScope:    types.BoolValue(app.InScope),
		MainTarget: types.BoolValue(app.MainTarget),
		CreatedAt:  types.StringValue(app.CreatedAt),
	}
}

// sameURL reports whether two application URLs differ only in ways Heist may
// normalize: scheme and host case, and a trailing slash.
func sameURL(a, b string) bool {
	if a == b {
		return true
	}
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	if errA != nil || errB != nil {
		return false
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) &&
		strings.EqualFold(ua.Host, ub.Host) &&
		strings.TrimSuffix(ua.Path, "/") == strings.TrimSuffix(ub.Path, "/") &&
		ua.RawQuery == ub.RawQuery
}
