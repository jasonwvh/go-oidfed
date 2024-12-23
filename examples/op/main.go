package main

import (
	"github.com/zachmann/go-oidfed/examples/op/config"
	"github.com/zachmann/go-oidfed/examples/op/jws"
	"github.com/zachmann/go-oidfed/pkg"
)

func main() {
	config.MustLoadConfig()
	jws.InitKeys("fed", "oidc")
	if config.Conf.UseResolveEndpoint {
		pkg.DefaultMetadataResolver = pkg.SmartRemoteMetadataResolver{}
	}
	initServer()
}
