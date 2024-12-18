package main

import (
	"encoding/json"
	"fmt"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/zachmann/go-oidfed/pkg"
	"log"
	"net/http"
)

func initServer() {
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

var _fedLeaf *pkg.FederationLeaf

func fedLeaf() *pkg.FederationLeaf {
	if _fedLeaf == nil {
		metadata := &pkg.Metadata{
			OpenIDProvider: &pkg.OpenIDProviderMetadata{
				Issuer:                conf.OidcProviderConfig.Issuer,
				AuthorizationEndpoint: conf.OidcProviderConfig.AuthorizationEndpoint,
				TokenEndpoint:         conf.OidcProviderConfig.TokenEndpoint,
				UserinfoEndpoint:      conf.OidcProviderConfig.UserinfoEndpoint,
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

func handleAuthorize(w http.ResponseWriter, r *http.Request) {
	// Handle the authorization request
	// This is a simplified example, you need to implement the full logic
	code := randASCIIString(32)
	state := r.URL.Query().Get("state")
	redirectURI := r.URL.Query().Get("redirect_uri")

	http.Redirect(w, r, fmt.Sprintf("%s?code=%s&state=%s", redirectURI, code, state), http.StatusFound)

	/*
		{
		  "typ": "oauth-authz-req+jwt",
		  "alg": "RS256",
		  "kid": "that-kid-which-points-to-a-jwk-contained-in-the-trust-chain",
		}
		.
		{
		  "aud": "https://op.example.org",
		  "client_id": "https://rp.example.com",
		  "exp": 1589699162,
		  "iat": 1589699102,
		  "iss": "https://rp.example.com",
		  "jti": "4d3ec0f81f134ee9a97e0449be6d32be",
		  "nonce": "4LX0mFMxdBjkGmtx7a8WIOnB",
		  "redirect_uri": "https://rp.example.com/authz_cb",
		  "response_type": "code",
		  "scope": "openid profile email address phone",
		  "state": "YmX8PM9I7WbNoMnnieKKBiptVW0sP2OZ",
		  "trust_chain" : [
		    "eyJhbGciOiJSUzI1NiIsImtpZCI6Ims1NEhRdERpYnlHY3M5WldWTWZ2aUhm ...",
		    "eyJhbGciOiJSUzI1NiIsImtpZCI6IkJYdmZybG5oQU11SFIwN2FqVW1BY0JS ...",
		    "eyJhbGciOiJSUzI1NiIsImtpZCI6IkJYdmZybG5oQU11SFIwN2FqVW1BY0JS ..."
		  ]
		}
	*/
	request := r.URL.Query().Get("request")
	fmt.Printf("Request: %s\n", request)
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
