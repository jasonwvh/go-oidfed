package main

import (
	"encoding/json"
	"fmt"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/zachmann/go-oidfed/examples/op/pkce"
	"github.com/zachmann/go-oidfed/pkg"
	"log"
	"net/http"
)

type stateData struct {
	codeChallange *pkce.PKCE
	issuer        string
}

var stateDB map[string]stateData

var authBuilder *pkg.RequestObjectProducer
var _fedLeaf *pkg.FederationLeaf

func fedLeaf() *pkg.FederationLeaf {
	if _fedLeaf == nil {
		metadata := &pkg.Metadata{
			OpenIDProvider: &pkg.OpenIDProviderMetadata{
				// Scope:                   "openid",
				Issuer:                "",
				AuthorizationEndpoint: "",
				TokenEndpoint:         "",
				UserinfoEndpoint:      "",
				RegistrationEndpoint:  "",
			},
			FederationEntity: &pkg.FederationEntityMetadata{
				OrganizationName: conf.OrganisationName,
			},
		}
		var err error
		_fedLeaf, err = pkg.NewFederationLeaf(
			conf.EntityID, conf.AuthorityHints, conf.TrustAnchors, metadata,
			pkg.NewEntityStatementSigner(
				getKey("fed"),
				jwa.ES512,
			), 86400, getKey("oidc"), jwa.ES512,
		)
		if err != nil {
			log.Fatal(err)
		}
	}
	_fedLeaf.TrustMarks = conf.TrustMarks
	return _fedLeaf
}

var redirectURI string

func handleEntityConfiguration(w http.ResponseWriter, r *http.Request) {
	var err error

	jwt, err := fedLeaf().EntityConfigurationJWT()
	if err != nil {
		log.Fatal(err)
	}
	w.Header().Set("Content-Type", "application/entity-statement+jwt")
	_, _ = w.Write(jwt)
}

func handleOIDCConfiguration(w http.ResponseWriter, r *http.Request) {
	oidcConfig := pkg.OpenIDProviderMetadata{
		Issuer:                                  "",
		AuthorizationEndpoint:                   "",
		TokenEndpoint:                           "",
		UserinfoEndpoint:                        "",
		RegistrationEndpoint:                    "",
		JWKSURI:                                 "",
		ResponseTypesSupported:                  []string{"code"},
		SubjectTypesSupported:                   []string{"public"},
		IDTokenSignedResponseAlgValuesSupported: []string{"RS256"},
	}
	res, _ := json.Marshal(oidcConfig)

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(res)
}

func initServer() {
	redirectURI = fmt.Sprintf("%s/%s", conf.EntityID, "redirect")
	stateDB = make(map[string]stateData)

	http.HandleFunc("/.well-known/openid-federation", handleEntityConfiguration)
	http.HandleFunc("/.well-known/openid-configuration", handleOIDCConfiguration)
	http.HandleFunc("/authorize", handleAuthorize)
	http.HandleFunc("/token", handleToken)
	http.HandleFunc("/userinfo", handleUserInfo)
	http.HandleFunc("/jwks", handleJWKS)
	http.HandleFunc("/logout", handleLogout)

	fmt.Printf("Serving on %s\n", conf.ServerAddr)
	if err := http.ListenAndServe(conf.ServerAddr, nil); err != nil {
		log.Fatal(err)
	}
}

func handleAuthorize(w http.ResponseWriter, r *http.Request) {
	// Handle the authorization request
	// This is a simplified example, you need to implement the full logic
	code := randASCIIString(32)
	state := r.URL.Query().Get("state")
	redirectURI := r.URL.Query().Get("redirect_uri")
	http.Redirect(w, r, fmt.Sprintf("%s?code=%s&state=%s", redirectURI, code, state), http.StatusFound)
}

func handleToken(w http.ResponseWriter, r *http.Request) {
	// Handle the token request
	// This is a simplified example, you need to implement the full logic
	tokenResponse := map[string]string{
		"access_token":  randASCIIString(32),
		"token_type":    "Bearer",
		"expires_in":    "3600",
		"id_token":      randASCIIString(32),
		"refresh_token": randASCIIString(32),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenResponse)
}

func handleUserInfo(w http.ResponseWriter, r *http.Request) {
	// Handle the user info request
	// This is a simplified example, you need to implement the full logic
	userInfo := map[string]string{
		"sub":   "1234567890",
		"name":  "John Doe",
		"email": "john.doe@example.com",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}

func handleJWKS(w http.ResponseWriter, r *http.Request) {
	// Serve the JSON Web Key Set
	jwks := getJWKS("oidc")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	// Handle the logout request
	// This is a simplified example, you need to implement the full logic
	http.Redirect(w, r, "/", http.StatusFound)
}
