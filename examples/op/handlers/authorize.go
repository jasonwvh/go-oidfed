package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/zachmann/go-oidfed/examples/op/session"
	"net/http"
	"net/url"
	"time"
)

func HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect_uri")
	cookie, err := r.Cookie("session_token")
	if err != nil || !session.IsValidSession(cookie.Value) {
		loginURL := "/login?redirect_uri=" + url.QueryEscape(redirectURI)
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	authorizationCode, _ := GenerateRandomCode(32)
	expiresAt := time.Now().Add(5 * time.Minute)
	username := r.URL.Query().Get("username")
	SaveAuthCode(authorizationCode, username, expiresAt)

	//http.Redirect(w, r, redirectURI+"?code="+authorizationCode, http.StatusFound)
	http.Redirect(w, r, "http://localhost:4444/token"+"?code="+authorizationCode, http.StatusFound)
}

func GenerateRandomCode(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}
