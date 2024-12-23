package handlers

import (
	"encoding/json"
	"github.com/golang-jwt/jwt"
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
	var req TokenRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Retrieve the authorization code from the database
	authCode, exists := GetAuthCode(req.Code)
	if !exists || time.Now().After(authCode.ExpiresAt) {
		http.Error(w, "Invalid or expired code", http.StatusUnauthorized)
		return
	}

	// Delete the authorization code from the database
	DeleteAuthCode(req.Code)

	// Create access token
	expirationTime := time.Now().Add(15 * time.Minute)
	accessTokenClaims := &Claims{
		Username: authCode.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)
	accessTokenString, err := accessToken.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Return access token
	json.NewEncoder(w).Encode(map[string]string{"access_token": accessTokenString})
}
