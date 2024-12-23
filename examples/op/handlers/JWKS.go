package handlers

import (
	"encoding/json"
	"github.com/zachmann/go-oidfed/examples/op/jws"
	"net/http"
)

func HandleJWKS(w http.ResponseWriter, r *http.Request) {
	// Serve the JSON Web Key Set
	jwks := jws.GetJWKS("oidc")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}
