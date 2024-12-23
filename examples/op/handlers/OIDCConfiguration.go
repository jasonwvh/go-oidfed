package handlers

import (
	"encoding/json"
	"github.com/zachmann/go-oidfed/pkg"
	"net/http"
)

func HandleOIDCConfiguration(w http.ResponseWriter, r *http.Request) {
	entity := fedLeaf().Metadata.OpenIDProvider
	oidcConfig := pkg.OpenIDProviderMetadata{
		Issuer:                                  entity.Issuer,
		AuthorizationEndpoint:                   entity.AuthorizationEndpoint,
		TokenEndpoint:                           entity.TokenEndpoint,
		UserinfoEndpoint:                        entity.UserinfoEndpoint,
		JWKSURI:                                 entity.JWKSURI,
		ResponseTypesSupported:                  []string{"code"},
		SubjectTypesSupported:                   []string{"public"},
		IDTokenSignedResponseAlgValuesSupported: []string{"RS256"},
	}
	res, _ := json.Marshal(oidcConfig)

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(res)
}
