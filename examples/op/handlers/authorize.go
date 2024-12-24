package handlers

import (
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

	authorizationCode := "auth_code_example"
	expiresAt := time.Now().Add(5 * time.Minute)
	username := r.URL.Query().Get("username")
	SaveAuthCode(authorizationCode, username, expiresAt)

	http.Redirect(w, r, redirectURI+"?code="+authorizationCode, http.StatusFound)
}
