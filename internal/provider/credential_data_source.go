package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	dschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/heist-security/heist-go/heist"
)

var (
	_ datasource.DataSourceWithConfigure = (*credentialDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*credentialsDataSource)(nil)
)

// hintFields describes the safe metadata the API returns about a
// credential's sign-in details.
var hintFields = []struct {
	name, description string
	typ               attr.Type
}{
	{"username", "Username.", types.StringType},
	{"email", "Email address.", types.StringType},
	{"phone", "Phone number.", types.StringType},
	{"phone_prefix", "Phone number prefix.", types.StringType},
	{"password_length", "Length of the password.", types.Int64Type},
	{"otp_length", "Length of the one-time password.", types.Int64Type},
	{"has_mfa", "Whether sign-in uses multi-factor authentication.", types.BoolType},
	{"masked_key", "API key with most characters masked.", types.StringType},
	{"header_name", "Header the key or token is sent in.", types.StringType},
	{"client_id", "OAuth client ID.", types.StringType},
	{"token_url", "OAuth token endpoint URL.", types.StringType},
	{"scope", "OAuth scope.", types.StringType},
	{"secret_names", "Names of CUSTOM secrets.", types.ListType{ElemType: types.StringType}},
	{"cookie_name", "Static cookie name.", types.StringType},
}

var hintAttrTypes = func() map[string]attr.Type {
	m := map[string]attr.Type{}
	for _, f := range hintFields {
		m[f.name] = f.typ
	}
	return m
}()

type hintModel struct {
	Username       types.String `tfsdk:"username"`
	Email          types.String `tfsdk:"email"`
	Phone          types.String `tfsdk:"phone"`
	PhonePrefix    types.String `tfsdk:"phone_prefix"`
	PasswordLength types.Int64  `tfsdk:"password_length"`
	OTPLength      types.Int64  `tfsdk:"otp_length"`
	HasMFA         types.Bool   `tfsdk:"has_mfa"`
	MaskedKey      types.String `tfsdk:"masked_key"`
	HeaderName     types.String `tfsdk:"header_name"`
	ClientID       types.String `tfsdk:"client_id"`
	TokenURL       types.String `tfsdk:"token_url"`
	Scope          types.String `tfsdk:"scope"`
	SecretNames    types.List   `tfsdk:"secret_names"`
	CookieName     types.String `tfsdk:"cookie_name"`
}

func hintValue(ctx context.Context, cred heist.Credential) (types.Object, diag.Diagnostics) {
	h := cred.Hint
	var diags diag.Diagnostics
	secretNames := types.ListNull(types.StringType)
	if h.SecretNames != nil {
		var d diag.Diagnostics
		secretNames, d = types.ListValueFrom(ctx, types.StringType, *h.SecretNames)
		diags.Append(d...)
	}
	obj, d := types.ObjectValueFrom(ctx, hintAttrTypes, hintModel{
		Username:       types.StringPointerValue(h.Username),
		Email:          types.StringPointerValue(h.Email),
		Phone:          types.StringPointerValue(h.Phone),
		PhonePrefix:    types.StringPointerValue(h.PhonePrefix),
		PasswordLength: int64Pointer(h.PasswordLength),
		OTPLength:      int64Pointer(h.OtpLength),
		HasMFA:         types.BoolPointerValue(h.HasMfa),
		MaskedKey:      types.StringPointerValue(h.MaskedKey),
		HeaderName:     types.StringPointerValue(h.HeaderName),
		ClientID:       types.StringPointerValue(h.ClientId),
		TokenURL:       types.StringPointerValue(h.TokenUrl),
		Scope:          types.StringPointerValue(h.Scope),
		SecretNames:    secretNames,
		CookieName:     types.StringPointerValue(h.CookieName),
	})
	diags.Append(d...)
	return obj, diags
}

func int64Pointer(f *float32) types.Int64 {
	if f == nil {
		return types.Int64Null()
	}
	return types.Int64Value(int64(*f))
}

func hintResourceAttributes() map[string]rschema.Attribute {
	attrs := map[string]rschema.Attribute{}
	for _, f := range hintFields {
		switch f.typ {
		case types.StringType:
			attrs[f.name] = rschema.StringAttribute{Description: f.description, Computed: true}
		case types.Int64Type:
			attrs[f.name] = rschema.Int64Attribute{Description: f.description, Computed: true}
		case types.BoolType:
			attrs[f.name] = rschema.BoolAttribute{Description: f.description, Computed: true}
		default:
			attrs[f.name] = rschema.ListAttribute{Description: f.description, Computed: true, ElementType: types.StringType}
		}
	}
	return attrs
}

func hintDataSourceAttributes() map[string]dschema.Attribute {
	attrs := map[string]dschema.Attribute{}
	for _, f := range hintFields {
		switch f.typ {
		case types.StringType:
			attrs[f.name] = dschema.StringAttribute{Description: f.description, Computed: true}
		case types.Int64Type:
			attrs[f.name] = dschema.Int64Attribute{Description: f.description, Computed: true}
		case types.BoolType:
			attrs[f.name] = dschema.BoolAttribute{Description: f.description, Computed: true}
		default:
			attrs[f.name] = dschema.ListAttribute{Description: f.description, Computed: true, ElementType: types.StringType}
		}
	}
	return attrs
}

// credentialDataModel is a credential's safe metadata and application links.
type credentialDataModel struct {
	ID             types.String          `tfsdk:"id"`
	Type           types.String          `tfsdk:"type"`
	AcceptedInvite types.Bool            `tfsdk:"accepted_invite"`
	LoginURL       types.String          `tfsdk:"login_url"`
	Instructions   types.String          `tfsdk:"instructions"`
	Hint           types.Object          `tfsdk:"hint"`
	Applications   []credentialLinkModel `tfsdk:"applications"`
}

type credentialLinkModel struct {
	ID        types.String `tfsdk:"id"`
	URL       types.String `tfsdk:"url"`
	IsPrimary types.Bool   `tfsdk:"is_primary"`
	RoleLevel types.Int64  `tfsdk:"role_level"`
	EntityID  types.String `tfsdk:"entity_id"`
}

// credentialDataAttributes returns the data source attributes of a
// credential. idRequired makes id an argument rather than a result.
func credentialDataAttributes(idRequired bool) map[string]dschema.Attribute {
	return map[string]dschema.Attribute{
		"id":              dschema.StringAttribute{Description: "Credential ID.", Required: idRequired, Computed: !idRequired},
		"type":            dschema.StringAttribute{Description: "Sign-in method.", Computed: true},
		"accepted_invite": dschema.BoolAttribute{Description: "Whether the account has accepted its invitation.", Computed: true},
		"login_url":       dschema.StringAttribute{Description: "URL of the login page.", Computed: true},
		"instructions":    dschema.StringAttribute{Description: "Sign-in instructions.", Computed: true},
		"hint": dschema.SingleNestedAttribute{
			Description: "Safe metadata about the sign-in details. Fields not used by the type are null.",
			Computed:    true,
			Attributes:  hintDataSourceAttributes(),
		},
		"applications": dschema.ListNestedAttribute{
			Description: "Applications the credential is linked to.",
			Computed:    true,
			NestedObject: dschema.NestedAttributeObject{Attributes: map[string]dschema.Attribute{
				"id":         dschema.StringAttribute{Description: "Application ID.", Computed: true},
				"url":        dschema.StringAttribute{Description: "Application URL.", Computed: true},
				"is_primary": dschema.BoolAttribute{Description: "Whether this is the primary credential of its tenant.", Computed: true},
				"role_level": dschema.Int64Attribute{Description: "Privilege level of the credential in the application.", Computed: true},
				"entity_id":  dschema.StringAttribute{Description: "Tenant the credential belongs to in the application.", Computed: true},
			}},
		},
	}
}

func credentialData(ctx context.Context, cred heist.Credential) (credentialDataModel, diag.Diagnostics) {
	hint, diags := hintValue(ctx, cred)
	m := credentialDataModel{
		ID:             types.StringValue(cred.Id),
		Type:           types.StringValue(string(cred.Type)),
		AcceptedInvite: types.BoolValue(cred.AcceptedInvite),
		LoginURL:       types.StringPointerValue(cred.LoginUrl),
		Instructions:   types.StringPointerValue(cred.Instructions),
		Hint:           hint,
		Applications:   make([]credentialLinkModel, len(cred.Applications)),
	}
	for i, app := range cred.Applications {
		m.Applications[i] = credentialLinkModel{
			ID:        types.StringValue(app.Id),
			URL:       types.StringValue(app.Url),
			IsPrimary: types.BoolValue(app.IsPrimary),
			RoleLevel: int64Pointer(app.RoleLevel),
			EntityID:  types.StringPointerValue(app.EntityId),
		}
	}
	return m, diags
}

func newCredentialDataSource() datasource.DataSource {
	return &credentialDataSource{}
}

type credentialDataSource struct {
	client *heist.ClientWithResponses
}

func (d *credentialDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_credential"
}

func (d *credentialDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = dschema.Schema{
		Description: "Safe metadata and application links of a credential. Secrets are never returned.",
		Attributes:  credentialDataAttributes(true),
	}
}

func (d *credentialDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = clientFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *credentialDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var id types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("id"), &id)...)
	if resp.Diagnostics.HasError() {
		return
	}
	parsed, ok := parseID(id.ValueString(), &resp.Diagnostics)
	if !ok {
		return
	}
	res, err := d.client.GetCredentialWithResponse(ctx, parsed)
	if err == nil && res.JSON200 == nil {
		err = errMissingBody
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read credential", err.Error())
		return
	}
	m, diags := credentialData(ctx, *res.JSON200)
	resp.Diagnostics.Append(diags...)
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

func newCredentialsDataSource() datasource.DataSource {
	return &credentialsDataSource{}
}

type credentialsDataSource struct {
	client *heist.ClientWithResponses
}

func (d *credentialsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_credentials"
}

func (d *credentialsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = dschema.Schema{
		Description: "Safe metadata and application links of every credential in the workspace. Secrets are never returned.",
		Attributes: map[string]dschema.Attribute{
			"credentials": dschema.ListNestedAttribute{
				Description:  "Credentials in the workspace.",
				Computed:     true,
				NestedObject: dschema.NestedAttributeObject{Attributes: credentialDataAttributes(false)},
			},
		},
	}
}

func (d *credentialsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = clientFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *credentialsDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	res, err := d.client.ListCredentialsWithResponse(ctx)
	if err == nil && res.JSON200 == nil {
		err = errMissingBody
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to list credentials", err.Error())
		return
	}
	var state struct {
		Credentials []credentialDataModel `tfsdk:"credentials"`
	}
	state.Credentials = make([]credentialDataModel, len(*res.JSON200))
	for i, cred := range *res.JSON200 {
		m, diags := credentialData(ctx, cred)
		resp.Diagnostics.Append(diags...)
		state.Credentials[i] = m
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}
