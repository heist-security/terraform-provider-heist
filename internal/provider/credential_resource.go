package provider

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/objectvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
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
	_ resource.ResourceWithConfigure      = (*credentialResource)(nil)
	_ resource.ResourceWithImportState    = (*credentialResource)(nil)
	_ resource.ResourceWithModifyPlan     = (*credentialResource)(nil)
	_ resource.ResourceWithValidateConfig = (*credentialResource)(nil)
)

// importedKey marks private state of an imported credential until its first
// apply. Values the API never returns are null after import; that apply
// adopts their configured values instead of replacing the credential.
const importedKey = "imported"

// createMu serializes credential creates, from requesting a generated email
// or phone to saving the credential. Heist reserves a generated email only
// when a credential is saved with it, so concurrent creates could be offered
// the same one. Resource instances aren't shared between requests, so the
// lock is package-level.
var createMu sync.Mutex

// credentialBlocks maps each credential type to the block holding its sign-in
// payload. GOOGLE has no payload and the anon block is optional.
var credentialBlocks = map[string]string{
	"BASIC":                     "basic",
	"HTTP_BASIC":                "basic",
	"EMAIL":                     "email",
	"SMS":                       "sms",
	"BANK_ID":                   "bank_id",
	"MICROSOFT":                 "microsoft",
	"GOOGLE":                    "",
	"API_KEY":                   "api_key",
	"OAUTH2_CLIENT_CREDENTIALS": "oauth2",
	"CUSTOM":                    "custom",
	"STATIC_COOKIE":             "static_cookie",
	"ANON":                      "anon",
}

func newCredentialResource() resource.Resource {
	return &credentialResource{}
}

type credentialResource struct {
	client *heist.ClientWithResponses
}

type credentialModel struct {
	ID                     types.String       `tfsdk:"id"`
	Type                   types.String       `tfsdk:"type"`
	LoginURL               types.String       `tfsdk:"login_url"`
	Instructions           types.String       `tfsdk:"instructions"`
	CustomHeaders          types.List         `tfsdk:"custom_header"`
	CustomHeadersWOVersion types.Int64        `tfsdk:"custom_headers_wo_version"`
	Basic                  *basicModel        `tfsdk:"basic"`
	Email                  *emailModel        `tfsdk:"email"`
	Microsoft              *emailModel        `tfsdk:"microsoft"`
	SMS                    *smsModel          `tfsdk:"sms"`
	BankID                 *bankIDModel       `tfsdk:"bank_id"`
	APIKey                 *apiKeyModel       `tfsdk:"api_key"`
	OAuth2                 *oauth2Model       `tfsdk:"oauth2"`
	Custom                 *customModel       `tfsdk:"custom"`
	StaticCookie           *staticCookieModel `tfsdk:"static_cookie"`
	Anon                   *anonModel         `tfsdk:"anon"`
	AcceptedInvite         types.Bool         `tfsdk:"accepted_invite"`
	Hint                   types.Object       `tfsdk:"hint"`
}

type nameValueModel struct {
	Name    types.String `tfsdk:"name"`
	ValueWO types.String `tfsdk:"value_wo"`
}

var nameValueType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"name":     types.StringType,
	"value_wo": types.StringType,
}}

type basicModel struct {
	Username          types.String `tfsdk:"username"`
	PasswordWO        types.String `tfsdk:"password_wo"`
	PasswordWOVersion types.Int64  `tfsdk:"password_wo_version"`
}

type emailModel struct {
	Email types.String `tfsdk:"email"`
}

type smsModel struct {
	Phone       types.String `tfsdk:"phone"`
	PhonePrefix types.String `tfsdk:"phone_prefix"`
}

type bankIDModel struct {
	Username         types.String `tfsdk:"username"`
	PasswordWO       types.String `tfsdk:"password_wo"`
	OTPWO            types.String `tfsdk:"otp_wo"`
	SecretsWOVersion types.Int64  `tfsdk:"secrets_wo_version"`
}

type apiKeyModel struct {
	APIKeyWO        types.String `tfsdk:"api_key_wo"`
	HeaderName      types.String `tfsdk:"header_name"`
	HeaderPrefix    types.String `tfsdk:"header_prefix"`
	APIKeyWOVersion types.Int64  `tfsdk:"api_key_wo_version"`
}

type oauth2Model struct {
	ClientID              types.String `tfsdk:"client_id"`
	ClientSecretWO        types.String `tfsdk:"client_secret_wo"`
	TokenURL              types.String `tfsdk:"token_url"`
	ClientAuthMethod      types.String `tfsdk:"client_auth_method"`
	Scope                 types.String `tfsdk:"scope"`
	HeaderName            types.String `tfsdk:"header_name"`
	HeaderPrefix          types.String `tfsdk:"header_prefix"`
	ClientSecretWOVersion types.Int64  `tfsdk:"client_secret_wo_version"`
}

type customModel struct {
	Email            types.String `tfsdk:"email"`
	Phone            types.String `tfsdk:"phone"`
	Secrets          types.List   `tfsdk:"secret"`
	SecretsWOVersion types.Int64  `tfsdk:"secrets_wo_version"`
}

type staticCookieModel struct {
	Name           types.String `tfsdk:"name"`
	ValueWO        types.String `tfsdk:"value_wo"`
	ValueWOVersion types.Int64  `tfsdk:"value_wo_version"`
}

type anonModel struct {
	Username types.String `tfsdk:"username"`
}

func (r *credentialResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_credential"
}

const credentialDescription = "A test account Heist signs in with. Set `type` and the block for that type. " +
	"The credential is created without application links. Only a new `basic` password (BASIC and HTTP_BASIC) " +
	"and the instructions and secrets of a CUSTOM credential are updated in place. Any other " +
	"change, including `type`, replaces the credential, which also removes its application links. Secrets are " +
	"write-only and need Terraform 1.11 or later."

func (r *credentialResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	// Generated email and phone values stay in state when unset.
	generated := []planmodifier.String{stringplanmodifier.UseStateForUnknown(), stringplanmodifier.RequiresReplace()}
	secret := func(desc string) schema.StringAttribute {
		return schema.StringAttribute{Description: desc, Optional: true, Sensitive: true, WriteOnly: true}
	}
	// Terraform enforces Required attributes of a single nested block even
	// when the block is absent, so they are Optional and required here when
	// the block is set.
	requires := func(names ...string) []validator.Object {
		exprs := make([]path.Expression, len(names))
		for i, name := range names {
			exprs[i] = path.MatchRelative().AtName(name)
		}
		return []validator.Object{objectvalidator.AlsoRequires(exprs...)}
	}
	version := func(desc string) schema.Int64Attribute {
		return schema.Int64Attribute{Description: desc, Optional: true}
	}
	typeNames := make([]string, 0, len(credentialBlocks))
	for t := range credentialBlocks {
		typeNames = append(typeNames, t)
	}
	slices.Sort(typeNames)

	resp.Schema = schema.Schema{
		Description: credentialDescription,
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description:   "Credential ID.",
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"type": schema.StringAttribute{
				Description:   "Sign-in method: " + strings.Join(typeNames, ", ") + ". Set the matching block; GOOGLE has none and `anon` is optional.",
				Required:      true,
				PlanModifiers: replace,
				Validators:    []validator.String{stringvalidator.OneOf(typeNames...)},
			},
			"login_url": schema.StringAttribute{
				Description:   "URL of the login page.",
				Optional:      true,
				PlanModifiers: replace,
			},
			"instructions": schema.StringAttribute{
				Description: "Sign-in instructions for Heist. Updated in place for CUSTOM credentials.",
				Optional:    true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplaceIf(
					func(ctx context.Context, req planmodifier.StringRequest, resp *stringplanmodifier.RequiresReplaceIfFuncResponse) {
						var credentialType types.String
						resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("type"), &credentialType)...)
						resp.RequiresReplace = credentialType.ValueString() != "CUSTOM"
					},
					"Changing instructions replaces the credential unless its type is CUSTOM.",
					"Changing instructions replaces the credential unless its type is CUSTOM.",
				)},
			},
			"custom_headers_wo_version": version("Change to send `custom_header` values again, which replaces the credential."),
			"accepted_invite": schema.BoolAttribute{
				Description: "Whether the account has accepted its invitation.",
				Computed:    true,
			},
			"hint": schema.SingleNestedAttribute{
				Description: "Safe metadata about the sign-in details. Fields not used by the type are null.",
				Computed:    true,
				Attributes:  hintResourceAttributes(),
			},
		},
		Blocks: map[string]schema.Block{
			"custom_header": schema.ListNestedBlock{
				Description: "An HTTP header sent with every request. Changing headers replaces the credential.",
				NestedObject: schema.NestedBlockObject{Attributes: map[string]schema.Attribute{
					"name":     schema.StringAttribute{Description: "Header name.", Required: true},
					"value_wo": schema.StringAttribute{Description: "Header value.", Required: true, Sensitive: true, WriteOnly: true},
				}},
			},
			"basic": schema.SingleNestedBlock{
				Description: "Username and password, for BASIC and HTTP_BASIC credentials.",
				Validators:  requires("username", "password_wo"),
				Attributes: map[string]schema.Attribute{
					"username":            schema.StringAttribute{Description: "Required. Username or email address.", Optional: true, PlanModifiers: replace},
					"password_wo":         secret("Required. Password."),
					"password_wo_version": version("Change to set `password_wo` as the new password, in place."),
				},
			},
			"email": schema.SingleNestedBlock{
				Description: "Email OTP or magic-link sign-in, for EMAIL credentials.",
				Attributes: map[string]schema.Attribute{
					"email": schema.StringAttribute{
						Description: "Heist-controlled address on tester.heisthq.com. Generated when unset.",
						Optional:    true, Computed: true, PlanModifiers: generated,
					},
				},
			},
			"microsoft": schema.SingleNestedBlock{
				Description: "Microsoft sign-in, for MICROSOFT credentials.",
				Attributes: map[string]schema.Attribute{
					"email": schema.StringAttribute{
						Description: "Heist email address. Generated when unset.",
						Optional:    true, Computed: true, PlanModifiers: generated,
					},
				},
			},
			"sms": schema.SingleNestedBlock{
				Description: "SMS OTP sign-in, for SMS credentials.",
				Attributes: map[string]schema.Attribute{
					"phone": schema.StringAttribute{
						Description: "Heist phone number. Assigned when unset.",
						Optional:    true, Computed: true, PlanModifiers: generated,
					},
					"phone_prefix": schema.StringAttribute{
						Description: "Phone number prefix. Read from Heist when unset.",
						Optional:    true, Computed: true, PlanModifiers: generated,
					},
				},
			},
			"bank_id": schema.SingleNestedBlock{
				Description: "BankID sign-in, for BANK_ID credentials.",
				Validators:  requires("username", "password_wo", "otp_wo"),
				Attributes: map[string]schema.Attribute{
					"username":           schema.StringAttribute{Description: "Required. Username.", Optional: true, PlanModifiers: replace},
					"password_wo":        secret("Required. Password."),
					"otp_wo":             secret("Required. One-time password seed."),
					"secrets_wo_version": version("Change to send `password_wo` and `otp_wo` again, which replaces the credential."),
				},
			},
			"api_key": schema.SingleNestedBlock{
				Description: "API key sent in a header, for API_KEY credentials.",
				Validators:  requires("api_key_wo", "header_name"),
				Attributes: map[string]schema.Attribute{
					"api_key_wo":         secret("Required. API key."),
					"header_name":        schema.StringAttribute{Description: "Required. Header the key is sent in.", Optional: true, PlanModifiers: replace},
					"header_prefix":      schema.StringAttribute{Description: "Prefix before the key, for example `Bearer`.", Optional: true},
					"api_key_wo_version": version("Change to send `api_key_wo` again, which replaces the credential."),
				},
			},
			"oauth2": schema.SingleNestedBlock{
				Description: "OAuth 2.0 client credentials, for OAUTH2_CLIENT_CREDENTIALS credentials.",
				Validators:  requires("client_id", "client_secret_wo", "token_url"),
				Attributes: map[string]schema.Attribute{
					"client_id":        schema.StringAttribute{Description: "Required. Client ID.", Optional: true, PlanModifiers: replace},
					"client_secret_wo": secret("Required. Client secret."),
					"token_url":        schema.StringAttribute{Description: "Required. Token endpoint URL.", Optional: true, PlanModifiers: replace},
					"client_auth_method": schema.StringAttribute{
						Description: "How the client authenticates to the token endpoint: `BODY` or `BASIC`.",
						Optional:    true,
						Validators:  []validator.String{stringvalidator.OneOf("BODY", "BASIC")},
					},
					"scope":                    schema.StringAttribute{Description: "Requested scope.", Optional: true, PlanModifiers: replace},
					"header_name":              schema.StringAttribute{Description: "Header the access token is sent in.", Optional: true},
					"header_prefix":            schema.StringAttribute{Description: "Prefix before the access token.", Optional: true},
					"client_secret_wo_version": version("Change to send `client_secret_wo` again, which replaces the credential."),
				},
			},
			"custom": schema.SingleNestedBlock{
				Description: "Custom sign-in described by `instructions`, for CUSTOM credentials. Secrets are updated in place.",
				Attributes: map[string]schema.Attribute{
					// The API keeps the email and phone of an existing CUSTOM
					// credential, so changing them replaces it.
					"email": schema.StringAttribute{
						Description: "Heist email address. Generated when unset.",
						Optional:    true, Computed: true, PlanModifiers: generated,
					},
					"phone": schema.StringAttribute{
						Description: "Heist phone number. Assigned by Heist when unset, if one is available.",
						Optional:    true, Computed: true, PlanModifiers: generated,
					},
					"secrets_wo_version": version("Change to send every `secret` value again, in place."),
				},
				Blocks: map[string]schema.Block{
					"secret": schema.ListNestedBlock{
						Description: "A named secret, such as a password or TOTP seed. Up to 20.",
						Validators:  []validator.List{listvalidator.SizeAtMost(20)},
						NestedObject: schema.NestedBlockObject{Attributes: map[string]schema.Attribute{
							"name":     schema.StringAttribute{Description: "Secret name.", Required: true},
							"value_wo": schema.StringAttribute{Description: "Secret value.", Required: true, Sensitive: true, WriteOnly: true},
						}},
					},
				},
			},
			"static_cookie": schema.SingleNestedBlock{
				Description: "A fixed session cookie, for STATIC_COOKIE credentials.",
				Validators:  requires("name", "value_wo"),
				Attributes: map[string]schema.Attribute{
					"name":             schema.StringAttribute{Description: "Required. Cookie name.", Optional: true, PlanModifiers: replace},
					"value_wo":         secret("Required. Cookie value."),
					"value_wo_version": version("Change to send `value_wo` again, which replaces the credential."),
				},
			},
			"anon": schema.SingleNestedBlock{
				Description: "Anonymous access, for ANON credentials. Optional.",
				Attributes: map[string]schema.Attribute{
					"username": schema.StringAttribute{Description: "Display name.", Optional: true, PlanModifiers: replace},
				},
			},
		},
	}
}

func (r *credentialResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFrom(req.ProviderData, &resp.Diagnostics)
}

// ValidateConfig requires the block for the credential type and no other.
func (r *credentialResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var credentialType types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("type"), &credentialType)...)
	if resp.Diagnostics.HasError() || credentialType.IsUnknown() || credentialType.IsNull() {
		return
	}
	want, ok := credentialBlocks[credentialType.ValueString()]
	if !ok {
		return // Reported by the type validator.
	}
	for _, block := range []string{"basic", "email", "microsoft", "sms", "bank_id", "api_key", "oauth2", "custom", "static_cookie", "anon"} {
		var v types.Object
		resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root(block), &v)...)
		if v.IsUnknown() {
			continue
		}
		switch {
		case block == want && v.IsNull() && block != "anon":
			resp.Diagnostics.AddAttributeError(path.Root(block), "Missing credential block",
				fmt.Sprintf("A %s credential needs a %s block, even an empty one.", credentialType.ValueString(), block))
		case block != want && !v.IsNull():
			resp.Diagnostics.AddAttributeError(path.Root(block), "Unexpected credential block",
				fmt.Sprintf("A %s credential can't have a %s block.", credentialType.ValueString(), block))
		}
	}
}

// unreadablePaths are values the API never returns whose changes replace the
// credential. Write-only values are always null in plans, so their versions
// stand in for them.
var unreadablePaths = []path.Path{
	path.Root("custom_header"),
	path.Root("custom_headers_wo_version"),
	path.Root("bank_id").AtName("secrets_wo_version"),
	path.Root("api_key").AtName("header_prefix"),
	path.Root("api_key").AtName("api_key_wo_version"),
	path.Root("oauth2").AtName("client_auth_method"),
	path.Root("oauth2").AtName("header_name"),
	path.Root("oauth2").AtName("header_prefix"),
	path.Root("oauth2").AtName("client_secret_wo_version"),
	path.Root("static_cookie").AtName("value_wo_version"),
}

// ModifyPlan replaces the credential when an unreadable value changes. After
// import those values are null in state, so the first plan adopts their
// configured values instead, and forces an update that clears the import
// marker.
func (r *credentialResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() || req.State.Raw.IsNull() {
		return
	}
	imported, diags := isImported(ctx, req.Private)
	resp.Diagnostics.Append(diags...)
	for _, p := range unreadablePaths {
		var planned, prior attr.Value
		resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, p, &planned)...)
		resp.Diagnostics.Append(req.State.GetAttribute(ctx, p, &prior)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if planned.Equal(prior) || (imported && isEmpty(prior)) {
			continue
		}
		resp.RequiresReplace.Append(p)
	}
	if imported {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("hint"), types.ObjectUnknown(hintAttrTypes))...)
	}
}

// isEmpty reports whether v is null or an empty list.
func isEmpty(v attr.Value) bool {
	if l, ok := v.(types.List); ok {
		return len(l.Elements()) == 0
	}
	return v.IsNull()
}

func (r *credentialResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan, config credentialModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	createMu.Lock()
	defer createMu.Unlock()
	body, diags := r.createBody(ctx, plan, config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	res, err := r.client.CreateCredentialWithResponse(ctx, body)
	if err == nil && res.JSON201 == nil {
		err = errMissingBody
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to create credential", err.Error())
		return
	}
	state, diags := credentialState(ctx, *res.JSON201, plan)
	resp.Diagnostics.Append(diags...)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// createBody builds the create request. Plan values are used for everything
// except write-only secrets, which only the configuration has.
func (r *credentialResource) createBody(ctx context.Context, plan, config credentialModel) (heist.CreateCredentialJSONRequestBody, diag.Diagnostics) {
	var diags diag.Diagnostics
	body := heist.CreateCredentialJSONRequestBody{
		Type: heist.CreateCredentialJSONBodyType(plan.Type.ValueString()),
		// Without applicationIds the API links every in-scope root
		// application. Links are managed separately.
		ApplicationIds: &[]uuid.UUID{},
		LoginUrl:       plan.LoginURL.ValueStringPointer(),
		Instructions:   plan.Instructions.ValueStringPointer(),
	}
	headers, d := nameValues(ctx, config.CustomHeaders)
	diags.Append(d...)
	if len(headers) > 0 {
		h := make([]struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		}, len(headers))
		for i, nv := range headers {
			h[i].Name, h[i].Value = nv.Name.ValueString(), nv.ValueWO.ValueString()
		}
		body.CustomHeaders = &h
	}

	// Request generated values only when needed, and at most once.
	var options *struct {
		Email        *string  `json:"email"`
		PhoneNumbers []string `json:"phoneNumbers"`
	}
	generatedEmail := func(v types.String) string {
		if !v.IsUnknown() && !v.IsNull() {
			return v.ValueString()
		}
		if options == nil {
			options, d = r.creationOptions(ctx)
			diags.Append(d...)
		}
		if options == nil || options.Email == nil {
			if !diags.HasError() {
				diags.AddError("No Heist email available", "Heist has no generated email address available. Set the email explicitly.")
			}
			return ""
		}
		return *options.Email
	}
	generatedPhone := func(v types.String) string {
		if !v.IsUnknown() && !v.IsNull() {
			return v.ValueString()
		}
		if options == nil {
			options, d = r.creationOptions(ctx)
			diags.Append(d...)
		}
		if options == nil || len(options.PhoneNumbers) == 0 {
			if !diags.HasError() {
				diags.AddError("No Heist phone available", "Heist has no phone number available. Set the phone explicitly.")
			}
			return ""
		}
		return options.PhoneNumbers[0]
	}

	switch {
	case plan.Basic != nil:
		body.Basic = &struct {
			Password string `json:"password"`
			Username string `json:"username"`
		}{Username: plan.Basic.Username.ValueString(), Password: config.Basic.PasswordWO.ValueString()}
	case plan.Email != nil:
		body.Email = &struct {
			Email string `json:"email"`
		}{Email: generatedEmail(plan.Email.Email)}
	case plan.Microsoft != nil:
		body.Microsoft = &struct {
			Email string `json:"email"`
		}{Email: generatedEmail(plan.Microsoft.Email)}
	case plan.SMS != nil:
		body.Sms = &struct {
			Phone       string  `json:"phone"`
			PhonePrefix *string `json:"phonePrefix"`
		}{Phone: generatedPhone(plan.SMS.Phone), PhonePrefix: knownStringPointer(plan.SMS.PhonePrefix)}
	case plan.BankID != nil:
		body.BankId = &struct {
			Otp      string `json:"otp"`
			Password string `json:"password"`
			Username string `json:"username"`
		}{Username: plan.BankID.Username.ValueString(), Password: config.BankID.PasswordWO.ValueString(), Otp: config.BankID.OTPWO.ValueString()}
	case plan.APIKey != nil:
		body.ApiKey = &struct {
			ApiKey       string  `json:"apiKey"`
			HeaderName   string  `json:"headerName"`
			HeaderPrefix *string `json:"headerPrefix"`
		}{ApiKey: config.APIKey.APIKeyWO.ValueString(), HeaderName: plan.APIKey.HeaderName.ValueString(), HeaderPrefix: plan.APIKey.HeaderPrefix.ValueStringPointer()}
	case plan.OAuth2 != nil:
		o := plan.OAuth2
		body.Oauth2 = &struct {
			ClientAuthMethod *heist.CreateCredentialJSONBodyOauth2ClientAuthMethod `json:"clientAuthMethod,omitempty"`
			ClientId         string                                                `json:"clientId"`
			ClientSecret     string                                                `json:"clientSecret"`
			HeaderName       *string                                               `json:"headerName"`
			HeaderPrefix     *string                                               `json:"headerPrefix"`
			Scope            *string                                               `json:"scope"`
			TokenUrl         string                                                `json:"tokenUrl"`
		}{
			ClientId:     o.ClientID.ValueString(),
			ClientSecret: config.OAuth2.ClientSecretWO.ValueString(),
			TokenUrl:     o.TokenURL.ValueString(),
			Scope:        o.Scope.ValueStringPointer(),
			HeaderName:   o.HeaderName.ValueStringPointer(),
			HeaderPrefix: o.HeaderPrefix.ValueStringPointer(),
		}
		if !o.ClientAuthMethod.IsNull() {
			m := heist.CreateCredentialJSONBodyOauth2ClientAuthMethod(o.ClientAuthMethod.ValueString())
			body.Oauth2.ClientAuthMethod = &m
		}
	case plan.Custom != nil:
		secrets, d := nameValues(ctx, config.Custom.Secrets)
		diags.Append(d...)
		body.Custom = &struct {
			Email   string  `json:"email"`
			Phone   *string `json:"phone"`
			Secrets []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"secrets"`
		}{Email: generatedEmail(plan.Custom.Email), Phone: knownStringPointer(plan.Custom.Phone)}
		body.Custom.Secrets = make([]struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		}, len(secrets))
		for i, nv := range secrets {
			body.Custom.Secrets[i].Name, body.Custom.Secrets[i].Value = nv.Name.ValueString(), nv.ValueWO.ValueString()
		}
	case plan.StaticCookie != nil:
		body.StaticCookie = &struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		}{Name: plan.StaticCookie.Name.ValueString(), Value: config.StaticCookie.ValueWO.ValueString()}
	case plan.Anon != nil:
		body.Anon = &struct {
			Username *string `json:"username"`
		}{Username: plan.Anon.Username.ValueStringPointer()}
	}
	return body, diags
}

func (r *credentialResource) creationOptions(ctx context.Context) (*struct {
	Email        *string  `json:"email"`
	PhoneNumbers []string `json:"phoneNumbers"`
}, diag.Diagnostics) {
	var diags diag.Diagnostics
	res, err := r.client.CredentialCreationOptionsWithResponse(ctx, nil)
	if err == nil && res.JSON200 == nil {
		err = errMissingBody
	}
	if err != nil {
		diags.AddError("Unable to get a Heist email or phone", err.Error())
		return nil, diags
	}
	return res.JSON200, diags
}

func (r *credentialResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state credentialModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	cred, found, diags := r.get(ctx, state.ID.ValueString())
	resp.Diagnostics.Append(diags...)
	if !found {
		resp.State.RemoveResource(ctx)
		return
	}
	if resp.Diagnostics.HasError() {
		return
	}
	newState, diags := credentialState(ctx, *cred, state)
	resp.Diagnostics.Append(diags...)
	resp.Diagnostics.Append(resp.State.Set(ctx, newState)...)
}

// get reads a credential. found is false only for a 404.
func (r *credentialResource) get(ctx context.Context, id string) (*heist.Credential, bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	parsed, ok := parseID(id, &diags)
	if !ok {
		return nil, true, diags
	}
	res, err := r.client.GetCredentialWithResponse(ctx, parsed)
	if heist.IsNotFound(err) {
		return nil, false, diags
	}
	if err == nil && res.JSON200 == nil {
		err = errMissingBody
	}
	if err != nil {
		diags.AddError("Unable to read credential", err.Error())
		return nil, true, diags
	}
	return res.JSON200, true, diags
}

// Update sets a new BASIC or HTTP_BASIC password or edits a CUSTOM
// credential's instructions and secrets. Every other planned change either replaces the credential or
// only records values in state.
func (r *credentialResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state, config credentialModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	imported, diags := isImported(ctx, req.Private)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	id, ok := parseID(state.ID.ValueString(), &resp.Diagnostics)
	if !ok {
		return
	}
	// After import, version changes only record the configured version.
	versionChanged := func(planned, prior types.Int64) bool {
		return !imported && !planned.Equal(prior)
	}

	var cred *heist.Credential
	var err error
	switch {
	case plan.Basic != nil && state.Basic != nil && versionChanged(plan.Basic.PasswordWOVersion, state.Basic.PasswordWOVersion):
		var res *heist.SetCredentialPasswordResponse
		res, err = r.client.SetCredentialPasswordWithResponse(ctx, id, heist.SetCredentialPasswordJSONRequestBody{
			Password: config.Basic.PasswordWO.ValueString(),
		})
		if err == nil {
			cred = res.JSON200
		}
	case plan.Custom != nil && state.Custom != nil:
		body, send, d := customUpdate(ctx, plan, state, config, versionChanged(plan.Custom.SecretsWOVersion, state.Custom.SecretsWOVersion))
		resp.Diagnostics.Append(d...)
		if resp.Diagnostics.HasError() || !send {
			break
		}
		var res *heist.UpdateCustomCredentialResponse
		res, err = r.client.UpdateCustomCredentialWithResponse(ctx, id, body)
		if err == nil {
			cred = res.JSON200
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}
	if err == nil && cred == nil {
		var found bool
		cred, found, diags = r.get(ctx, id.String())
		resp.Diagnostics.Append(diags...)
		if !found {
			err = fmt.Errorf("credential %s not found", id)
		}
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to update credential", err.Error())
	}
	if resp.Diagnostics.HasError() {
		return
	}
	newState, diags := credentialState(ctx, *cred, plan)
	resp.Diagnostics.Append(diags...)
	resp.Diagnostics.Append(resp.State.Set(ctx, newState)...)
	resp.Diagnostics.Append(resp.Private.SetKey(ctx, importedKey, nil)...)
}

// customUpdate builds a CUSTOM edit of instructions and secrets. Secrets
// already stored are sent by name only, which keeps their values, unless the
// secrets version changed. send is false when neither has changed. The API
// ignores email and phone for an existing CUSTOM credential.
func customUpdate(ctx context.Context, plan, state, config credentialModel, resendSecrets bool) (body heist.UpdateCustomCredentialJSONRequestBody, send bool, diags diag.Diagnostics) {
	secrets, d := nameValues(ctx, config.Custom.Secrets)
	diags.Append(d...)
	stored, d := nameValues(ctx, state.Custom.Secrets)
	diags.Append(d...)
	storedNames := map[string]bool{}
	for _, s := range stored {
		storedNames[s.Name.ValueString()] = true
	}
	body = heist.UpdateCustomCredentialJSONRequestBody{
		Instructions: plan.Instructions.ValueStringPointer(),
	}
	body.Secrets = make([]struct {
		Name  string  `json:"name"`
		Value *string `json:"value"`
	}, len(secrets))
	for i, s := range secrets {
		body.Secrets[i].Name = s.Name.ValueString()
		if resendSecrets || !storedNames[s.Name.ValueString()] {
			body.Secrets[i].Value = s.ValueWO.ValueStringPointer()
		}
	}
	send = resendSecrets ||
		!plan.Instructions.Equal(state.Instructions) ||
		!plan.Custom.Secrets.Equal(state.Custom.Secrets)
	return body, send, diags
}

func (r *credentialResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state credentialModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id, ok := parseID(state.ID.ValueString(), &resp.Diagnostics)
	if !ok {
		return
	}
	_, err := r.client.DeleteCredentialWithResponse(ctx, id)
	if err != nil && !heist.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete credential", err.Error())
	}
}

func (r *credentialResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
	resp.Diagnostics.Append(resp.Private.SetKey(ctx, importedKey, []byte("true"))...)
}

// privateGetter is implemented by the framework's private state data.
type privateGetter interface {
	GetKey(context.Context, string) ([]byte, diag.Diagnostics)
}

func isImported(ctx context.Context, private privateGetter) (bool, diag.Diagnostics) {
	v, diags := private.GetKey(ctx, importedKey)
	return len(v) > 0, diags
}

// credentialState builds state from the API's safe metadata. Values the API
// doesn't return, and secrets, which are always null, come from prior: the
// plan after a create or update, or the state on refresh.
func credentialState(ctx context.Context, cred heist.Credential, prior credentialModel) (credentialModel, diag.Diagnostics) {
	h := cred.Hint
	hint, diags := hintValue(ctx, cred)
	m := credentialModel{
		ID:                     types.StringValue(cred.Id),
		Type:                   types.StringValue(string(cred.Type)),
		LoginURL:               types.StringPointerValue(cred.LoginUrl),
		Instructions:           types.StringPointerValue(cred.Instructions),
		CustomHeaders:          prior.CustomHeaders,
		CustomHeadersWOVersion: prior.CustomHeadersWOVersion,
		AcceptedInvite:         types.BoolValue(cred.AcceptedInvite),
		Hint:                   hint,
	}
	if m.CustomHeaders.IsNull() || m.CustomHeaders.IsUnknown() {
		m.CustomHeaders = types.ListNull(nameValueType)
	}
	str := types.StringPointerValue
	switch cred.Type {
	case heist.CredentialTypeBASIC, heist.CredentialTypeHTTPBASIC:
		m.Basic = &basicModel{Username: str(h.Username), PasswordWO: types.StringNull()}
		if prior.Basic != nil {
			m.Basic.PasswordWOVersion = prior.Basic.PasswordWOVersion
		}
	case heist.CredentialTypeEMAIL:
		m.Email = &emailModel{Email: str(h.Email)}
	case heist.CredentialTypeMICROSOFT:
		m.Microsoft = &emailModel{Email: str(h.Email)}
	case heist.CredentialTypeSMS:
		m.SMS = &smsModel{Phone: str(h.Phone), PhonePrefix: str(h.PhonePrefix)}
	case heist.CredentialTypeBANKID:
		m.BankID = &bankIDModel{Username: str(h.Username), PasswordWO: types.StringNull(), OTPWO: types.StringNull()}
		if prior.BankID != nil {
			m.BankID.SecretsWOVersion = prior.BankID.SecretsWOVersion
		}
	case heist.CredentialTypeAPIKEY:
		m.APIKey = &apiKeyModel{APIKeyWO: types.StringNull(), HeaderName: str(h.HeaderName)}
		if prior.APIKey != nil {
			m.APIKey.HeaderPrefix = prior.APIKey.HeaderPrefix
			m.APIKey.APIKeyWOVersion = prior.APIKey.APIKeyWOVersion
		}
	case heist.CredentialTypeOAUTH2CLIENTCREDENTIALS:
		m.OAuth2 = &oauth2Model{ClientID: str(h.ClientId), ClientSecretWO: types.StringNull(), TokenURL: str(h.TokenUrl), Scope: str(h.Scope)}
		if p := prior.OAuth2; p != nil {
			m.OAuth2.ClientAuthMethod = p.ClientAuthMethod
			m.OAuth2.HeaderName = p.HeaderName
			m.OAuth2.HeaderPrefix = p.HeaderPrefix
			m.OAuth2.ClientSecretWOVersion = p.ClientSecretWOVersion
		}
	case heist.CredentialTypeCUSTOM:
		m.Custom = &customModel{Email: str(h.Email), Phone: str(h.Phone)}
		var priorSecrets types.List
		if prior.Custom != nil {
			priorSecrets = prior.Custom.Secrets
			m.Custom.SecretsWOVersion = prior.Custom.SecretsWOVersion
		}
		var names []string
		if h.SecretNames != nil {
			names = *h.SecretNames
		}
		secrets, d := secretList(ctx, names, priorSecrets)
		diags.Append(d...)
		m.Custom.Secrets = secrets
	case heist.CredentialTypeSTATICCOOKIE:
		m.StaticCookie = &staticCookieModel{Name: str(h.CookieName), ValueWO: types.StringNull()}
		if prior.StaticCookie != nil {
			m.StaticCookie.ValueWOVersion = prior.StaticCookie.ValueWOVersion
		}
	case heist.CredentialTypeANON:
		// The block is optional, so keep it absent unless configured or
		// the API reports a username.
		if prior.Anon != nil || h.Username != nil {
			m.Anon = &anonModel{Username: str(h.Username)}
		}
	}
	return m, diags
}

// secretList returns CUSTOM secret names as state, keeping the prior order
// when the names are unchanged.
func secretList(ctx context.Context, names []string, prior types.List) (types.List, diag.Diagnostics) {
	priorSecrets, diags := nameValues(ctx, prior)
	priorNames := make([]string, len(priorSecrets))
	for i, s := range priorSecrets {
		priorNames[i] = s.Name.ValueString()
	}
	if slices.Equal(slices.Sorted(slices.Values(names)), slices.Sorted(slices.Values(priorNames))) {
		names = priorNames
	}
	secrets := make([]nameValueModel, len(names))
	for i, name := range names {
		secrets[i] = nameValueModel{Name: types.StringValue(name), ValueWO: types.StringNull()}
	}
	list, d := types.ListValueFrom(ctx, nameValueType, secrets)
	diags.Append(d...)
	return list, diags
}

// nameValues decodes a list of name and value blocks. Null and unknown lists
// decode as empty.
func nameValues(ctx context.Context, l types.List) ([]nameValueModel, diag.Diagnostics) {
	var out []nameValueModel
	if l.IsNull() || l.IsUnknown() {
		return out, nil
	}
	diags := l.ElementsAs(ctx, &out, false)
	return out, diags
}

// knownStringPointer returns nil for null or unknown values.
func knownStringPointer(v types.String) *string {
	if v.IsUnknown() {
		return nil
	}
	return v.ValueStringPointer()
}
