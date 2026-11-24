// Package provider implements the Heist Terraform provider on top of the
// public Heist Go SDK.
package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/heist-security/heist-go/heist"
)

// New returns a constructor for the provider at the given release version.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &heistProvider{version: version}
	}
}

type heistProvider struct {
	version string
}

type providerModel struct {
	AccessToken  types.String `tfsdk:"access_token"`
	ClientID     types.String `tfsdk:"client_id"`
	ClientSecret types.String `tfsdk:"client_secret"`
	TokenURL     types.String `tfsdk:"token_url"`
	ServerURL    types.String `tfsdk:"server_url"`
}

func (p *heistProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "heist"
	resp.Version = p.version
}

func (p *heistProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage Heist workspace configuration through the Heist external REST API.",
		Attributes: map[string]schema.Attribute{
			"access_token": schema.StringAttribute{
				Description: "Access token of a Heist OAuth app. " +
					"Conflicts with `client_id` and `client_secret`. " +
					"Defaults to the `HEIST_ACCESS_TOKEN` environment variable unless `client_id` or `client_secret` is set.",
				Optional:  true,
				Sensitive: true,
			},
			"client_id": schema.StringAttribute{
				Description: "Client ID of a Heist OAuth app, created in Settings → OAuth apps. The provider exchanges it and `client_secret` for " +
					"access tokens and refreshes them before they expire. Requires `client_secret`. " +
					"Defaults to the `HEIST_CLIENT_ID` environment variable unless `access_token` is set.",
				Optional: true,
			},
			"client_secret": schema.StringAttribute{
				Description: "Client secret of a Heist OAuth app. Requires `client_id`. " +
					"Defaults to the `HEIST_CLIENT_SECRET` environment variable unless `access_token` is set.",
				Optional:  true,
				Sensitive: true,
			},
			"token_url": schema.StringAttribute{
				Description: "OAuth token endpoint used with `client_id` and `client_secret`. " +
					"Defaults to the `HEIST_TOKEN_URL` environment variable, then to " + heist.DefaultTokenURL + ".",
				Optional: true,
			},
			"server_url": schema.StringAttribute{
				Description: "Heist external REST API URL, including the `/external` path prefix. " +
					"Defaults to the `HEIST_SERVER_URL` environment variable, then to " + heist.DefaultServerURL + ".",
				Optional: true,
			},
		},
	}
}

func (p *heistProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if config.AccessToken.IsUnknown() || config.ClientID.IsUnknown() || config.ClientSecret.IsUnknown() ||
		config.TokenURL.IsUnknown() || config.ServerURL.IsUnknown() {
		resp.Diagnostics.AddError("Unknown Heist provider configuration",
			"Provider attributes must be known before apply. Set them from variables or the environment "+
				"rather than from resources created in the same configuration.")
		return
	}

	// Credentials in the provider configuration take precedence: when it sets
	// one kind, the environment variables for the other kind are ignored.
	// Each attribute of the chosen kind still falls back to its own
	// environment variable, so a client ID in configuration can pair with
	// HEIST_CLIENT_SECRET.
	token := config.AccessToken.ValueString()
	clientID := config.ClientID.ValueString()
	clientSecret := config.ClientSecret.ValueString()
	configToken := token != ""
	configClient := clientID != "" || clientSecret != ""
	if !configClient {
		token = valueOrEnv(config.AccessToken, "HEIST_ACCESS_TOKEN")
	}
	if !configToken {
		clientID = valueOrEnv(config.ClientID, "HEIST_CLIENT_ID")
		clientSecret = valueOrEnv(config.ClientSecret, "HEIST_CLIENT_SECRET")
	}

	var tokens heist.TokenSource
	switch {
	case token != "" && (clientID != "" || clientSecret != ""):
		resp.Diagnostics.AddError("Conflicting Heist credentials",
			"Set either access_token (HEIST_ACCESS_TOKEN) or client_id and client_secret "+
				"(HEIST_CLIENT_ID and HEIST_CLIENT_SECRET), not both. Credentials in the provider "+
				"configuration take precedence over the environment.")
		return
	case token != "":
		tokens = heist.StaticToken(token)
	case clientID != "" && clientSecret != "":
		tokens = &heist.ClientCredentials{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			TokenURL:     valueOrEnv(config.TokenURL, "HEIST_TOKEN_URL"),
		}
	case clientID != "" || clientSecret != "":
		resp.Diagnostics.AddError("Incomplete Heist client credentials",
			"Set both client_id (HEIST_CLIENT_ID) and client_secret (HEIST_CLIENT_SECRET).")
		return
	default:
		resp.Diagnostics.AddError("Missing Heist credentials",
			"Set client_id and client_secret (HEIST_CLIENT_ID and HEIST_CLIENT_SECRET), "+
				"or access_token (HEIST_ACCESS_TOKEN), in the provider configuration or the environment.")
		return
	}

	client, err := heist.New(tokens, heist.Config{
		ServerURL: valueOrEnv(config.ServerURL, "HEIST_SERVER_URL"),
		UserAgent: "terraform-provider-heist/" + p.version,
	})
	if err != nil {
		resp.Diagnostics.AddError("Unable to create Heist client", err.Error())
		return
	}
	resp.ResourceData = client
	resp.DataSourceData = client
}

// valueOrEnv returns the configured value, or the environment variable when
// the attribute is unset or empty.
func valueOrEnv(v types.String, env string) string {
	if s := v.ValueString(); s != "" {
		return s
	}
	return os.Getenv(env)
}

func (p *heistProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		newApplicationResource,
		newScopeRuleResource,
	}
}

func (p *heistProvider) DataSources(context.Context) []func() datasource.DataSource {
	return nil
}
