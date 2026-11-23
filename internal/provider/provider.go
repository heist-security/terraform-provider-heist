// Package provider implements the Heist Terraform provider on top of the
// public Heist Go SDK.
package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
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
	AccessToken types.String `tfsdk:"access_token"`
	ServerURL   types.String `tfsdk:"server_url"`
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
				Description: "Access token of a Heist OAuth app, created in Settings → OAuth apps. " +
					"Defaults to the `HEIST_ACCESS_TOKEN` environment variable.",
				Optional:  true,
				Sensitive: true,
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
	if config.AccessToken.IsUnknown() || config.ServerURL.IsUnknown() {
		resp.Diagnostics.AddError("Unknown Heist provider configuration",
			"access_token and server_url must be known before apply. Set them from variables or the environment "+
				"rather than from resources created in the same configuration.")
		return
	}

	token := config.AccessToken.ValueString()
	if token == "" {
		token = os.Getenv("HEIST_ACCESS_TOKEN")
	}
	if token == "" {
		resp.Diagnostics.AddAttributeError(path.Root("access_token"), "Missing Heist access token",
			"Set access_token in the provider configuration or the HEIST_ACCESS_TOKEN environment variable.")
		return
	}
	serverURL := config.ServerURL.ValueString()
	if serverURL == "" {
		serverURL = os.Getenv("HEIST_SERVER_URL")
	}

	client, err := heist.New(heist.StaticToken(token), heist.Config{
		ServerURL: serverURL,
		UserAgent: "terraform-provider-heist/" + p.version,
	})
	if err != nil {
		resp.Diagnostics.AddError("Unable to create Heist client", err.Error())
		return
	}
	resp.ResourceData = client
	resp.DataSourceData = client
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
