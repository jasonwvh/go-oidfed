package handlers

import (
	"fmt"
	"net/http"
	"net/url"
	"time"
)

func HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	// Check if user is authenticated (this is a simplified example)
	if r.URL.Query().Get("authenticated") != "true" {
		// Redirect to login page with the original request URL as a query parameter
		loginURL := "/login?redirect_uri=" + url.QueryEscape(r.URL.String())
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// Generate authorization code (simplified example)
	authorizationCode := "auth_code_example"
	expiresAt := time.Now().Add(5 * time.Minute)
	username := r.URL.Query().Get("username")

	// Save the authorization code in the database
	SaveAuthCode(authorizationCode, username, expiresAt)

	// Redirect back to the client with the authorization code
	redirectURI := r.URL.Query().Get("redirect_uri")
	http.Redirect(w, r, redirectURI+"?code="+authorizationCode, http.StatusFound)

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
