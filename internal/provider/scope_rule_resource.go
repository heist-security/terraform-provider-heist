package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/heist-security/heist-go/heist"
)

var (
	_ resource.ResourceWithConfigure   = (*scopeRuleResource)(nil)
	_ resource.ResourceWithImportState = (*scopeRuleResource)(nil)
)

func newScopeRuleResource() resource.Resource {
	return &scopeRuleResource{}
}

type scopeRuleResource struct {
	client *heist.ClientWithResponses
}

type scopeRuleModel struct {
	ID        types.String `tfsdk:"id"`
	Pattern   types.String `tfsdk:"pattern"`
	Action    types.String `tfsdk:"action"`
	CreatedAt types.String `tfsdk:"created_at"`
}

func (r *scopeRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_scope_rule"
}

func (r *scopeRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A workspace URL scope rule. `ALLOW` rules expand URL scope and `BLOCK` rules take precedence " +
			"over them. Rules cannot be edited, so changing any argument replaces the rule.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description:   "Scope rule ID.",
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"pattern": schema.StringAttribute{
				Description: "Glob matched against the URL host (including port) and path, for example " +
					"`example.com/private/**` or `*.example.com/**`. Omit the scheme, query string and fragment.",
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"action": schema.StringAttribute{
				Description:   "`ALLOW` or `BLOCK`.",
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators:    []validator.String{stringvalidator.OneOf("ALLOW", "BLOCK")},
			},
			"created_at": schema.StringAttribute{
				Description:   "When the rule was created.",
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *scopeRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFrom(req.ProviderData, &resp.Diagnostics)
}

func (r *scopeRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan scopeRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	res, err := r.client.CreateScopeRuleWithResponse(ctx, heist.CreateScopeRuleJSONRequestBody{
		Pattern: plan.Pattern.ValueString(),
		Action:  heist.CreateScopeRuleJSONBodyAction(plan.Action.ValueString()),
	})
	if err == nil && res.JSON201 == nil {
		err = errMissingBody
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to create scope rule", err.Error())
		return
	}
	plan.ID = types.StringValue(res.JSON201.Id)
	plan.CreatedAt = types.StringValue(res.JSON201.CreatedAt)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *scopeRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state scopeRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id, ok := parseID(state.ID.ValueString(), &resp.Diagnostics)
	if !ok {
		return
	}
	res, err := r.client.GetScopeRuleWithResponse(ctx, id)
	if heist.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err == nil && res.JSON200 == nil {
		err = errMissingBody
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read scope rule", err.Error())
		return
	}
	rule := res.JSON200
	// Rules are immutable, so keep the configured pattern and action unless
	// importing. This avoids replacing a rule whose pattern the API normalized.
	if state.Pattern.IsNull() {
		state.Pattern = types.StringValue(rule.Pattern)
		state.Action = types.StringValue(string(rule.Action))
	}
	state.CreatedAt = types.StringValue(rule.CreatedAt)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Update is never called: every configurable attribute requires replacement.
func (r *scopeRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Scope rules cannot be updated", "This is a provider bug: every scope rule change should replace the rule.")
}

func (r *scopeRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state scopeRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id, ok := parseID(state.ID.ValueString(), &resp.Diagnostics)
	if !ok {
		return
	}
	if _, err := r.client.DeleteScopeRuleWithResponse(ctx, id); err != nil && !heist.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete scope rule", err.Error())
	}
}

func (r *scopeRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
