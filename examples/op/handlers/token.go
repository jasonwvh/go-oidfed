package handlers

import (
	"encoding/json"
	"github.com/golang-jwt/jwt"
	"github.com/zachmann/go-oidfed/examples/op/jws"
	"github.com/zachmann/go-oidfed/pkg"
	"net/http"
	"sync"
	"time"
)

type TokenRequest struct {
	Code string `json:"code"`
}

type AuthCode struct {
	Code      string
	Username  string
	ExpiresAt time.Time
}

var authCodes = make(map[string]AuthCode)

var mu sync.Mutex

// SaveAuthCode saves an authorization code in the database
func SaveAuthCode(code, username string, expiresAt time.Time) {
	mu.Lock()
	defer mu.Unlock()
	authCodes[code] = AuthCode{
		Code:      code,
		Username:  username,
		ExpiresAt: expiresAt,
	}
}

// GetAuthCode retrieves an authorization code from the database
func GetAuthCode(code string) (AuthCode, bool) {
	mu.Lock()
	defer mu.Unlock()
	authCode, exists := authCodes[code]
	return authCode, exists
}

// DeleteAuthCode deletes an authorization code from the database
func DeleteAuthCode(code string) {
	mu.Lock()
	defer mu.Unlock()
	delete(authCodes, code)
}

func HandleToken(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")

	authCode, exists := GetAuthCode(code)
	if !exists || time.Now().After(authCode.ExpiresAt) {
		http.Error(w, "Invalid or expired code", http.StatusUnauthorized)
		return
	}
	DeleteAuthCode(code)

	expirationTime := time.Now().Add(15 * time.Minute)
	jwks := jws.GetJWKS("oidc")
	openidProvider := fedLeaf().EntityConfigurationPayload().Metadata.OpenIDProvider
	metadata := pkg.Metadata{OpenIDProvider: openidProvider}
	accessTokenClaims := &Claims{
		Username: authCode.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
		JWKS:     *jwks,
		Metadata: metadata,
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)
	accessTokenString, err := accessToken.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"access_token": accessTokenString})
}
