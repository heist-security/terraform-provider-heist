package provider

import (
	"context"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/heist-security/heist-go/heist"
)

var _ datasource.DataSourceWithConfigure = (*applicationsDataSource)(nil)

func newApplicationsDataSource() datasource.DataSource {
	return &applicationsDataSource{}
}

type applicationsDataSource struct {
	client *heist.ClientWithResponses
}

type applicationsDataModel struct {
	InScope             types.Bool             `tfsdk:"in_scope"`
	RootOnly            types.Bool             `tfsdk:"root_only"`
	RequiresReview      types.Bool             `tfsdk:"requires_review"`
	ParentApplicationID types.String           `tfsdk:"parent_application_id"`
	Search              types.String           `tfsdk:"search"`
	Applications        []applicationDataModel `tfsdk:"applications"`
}

func (d *applicationsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_applications"
}

func (d *applicationsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Lists the applications in the workspace that match every filter set, including " +
			"applications Heist discovered and ones created outside Terraform.",
		Attributes: map[string]schema.Attribute{
			"in_scope": schema.BoolAttribute{
				Description: "Only applications that are (`true`) or are not (`false`) in testing scope.",
				Optional:    true,
			},
			"root_only": schema.BoolAttribute{
				Description: "Only applications without a parent application when `true`.",
				Optional:    true,
			},
			"requires_review": schema.BoolAttribute{
				Description: "Only applications that do (`true`) or do not (`false`) need review.",
				Optional:    true,
			},
			"parent_application_id": schema.StringAttribute{
				Description: "Only applications discovered under the application with this ID.",
				Optional:    true,
			},
			"search": schema.StringAttribute{
				Description: "Only applications matching this text, as the Heist API's application search defines it.",
				Optional:    true,
			},
			"applications": schema.ListNestedAttribute{
				Description:  "Matching applications.",
				Computed:     true,
				NestedObject: schema.NestedAttributeObject{Attributes: applicationAttributes()},
			},
		},
	}
}

func (d *applicationsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = clientFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *applicationsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state applicationsDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := heist.ListApplicationsParams{
		Size:           &maxPageSize,
		InScope:        boolParam[heist.ListApplicationsParamsInScope](state.InScope),
		RootOnly:       boolParam[heist.ListApplicationsParamsRootOnly](state.RootOnly),
		RequiresReview: boolParam[heist.ListApplicationsParamsRequiresReview](state.RequiresReview),
		Search:         state.Search.ValueStringPointer(),
	}
	if !state.ParentApplicationID.IsNull() {
		id, ok := parseID(state.ParentApplicationID.ValueString(), &resp.Diagnostics)
		if !ok {
			return
		}
		params.ParentApplicationId = &id
	}

	state.Applications = []applicationDataModel{}
	for app, err := range d.client.AllApplications(ctx, params) {
		if err != nil {
			resp.Diagnostics.AddError("Unable to list applications", err.Error())
			return
		}
		state.Applications = append(state.Applications, applicationData(app))
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// boolParam converts an optional boolean to the API's "true"/"false" query
// parameter, or nil when it is not set.
func boolParam[T ~string](v types.Bool) *T {
	if v.IsNull() {
		return nil
	}
	p := T(strconv.FormatBool(v.ValueBool()))
	return &p
}
