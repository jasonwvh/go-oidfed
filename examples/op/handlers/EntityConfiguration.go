package handlers

import (
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/zachmann/go-oidfed/examples/op/config"
	_ "github.com/zachmann/go-oidfed/examples/op/config"
	"github.com/zachmann/go-oidfed/examples/op/jws"
	"github.com/zachmann/go-oidfed/pkg"
	"log"
	"net/http"
)

var _fedLeaf *pkg.FederationLeaf

func fedLeaf() *pkg.FederationLeaf {
	if _fedLeaf == nil {
		metadata := &pkg.Metadata{
			OpenIDProvider: &pkg.OpenIDProviderMetadata{
				Issuer:                config.Conf.OidcProviderConfig.Issuer,
				AuthorizationEndpoint: config.Conf.OidcProviderConfig.AuthorizationEndpoint,
				TokenEndpoint:         config.Conf.OidcProviderConfig.TokenEndpoint,
				UserinfoEndpoint:      config.Conf.OidcProviderConfig.UserinfoEndpoint,
			},
			FederationEntity: &pkg.FederationEntityMetadata{
				OrganizationName: config.Conf.OrganisationName,
			},
		}
		var err error
		_fedLeaf, err = pkg.NewFederationLeaf(
			config.Conf.EntityID, config.Conf.AuthorityHints, config.Conf.TrustAnchors, metadata,
			pkg.NewEntityStatementSigner(
				jws.GetKey("fed"),
				jwa.ES512,
			), 86400, jws.GetKey("oidc"), jwa.ES512,
		)
		if err != nil {
			log.Fatal(err)
		}
	}
	_fedLeaf.TrustMarks = config.Conf.TrustMarks
	return _fedLeaf
}

func HandleEntityConfiguration(w http.ResponseWriter, r *http.Request) {
	var err error

	jwt, err := fedLeaf().EntityConfigurationJWT()
	if err != nil {
		log.Fatal(err)
	}
	w.Header().Set("Content-Type", "application/entity-statement+jwt")
	_, _ = w.Write(jwt)
}
