// Command terraform-provider-heist is the Terraform provider for Heist.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/heist-security/terraform-provider-heist/internal/provider"
)

// version is set by release builds with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider with support for debuggers such as delve")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/heist-security/heist",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
