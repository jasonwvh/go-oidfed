package handlers

import (
	"github.com/golang-jwt/jwt"
	"github.com/zachmann/go-oidfed/examples/op/session"
	"html/template"
	"net/http"
	"time"
)

var jwtKey = []byte("my_secret_key")

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// LoginPageHandler serves the login page
func LoginPageHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/login.gohtml")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	redirectURI := r.URL.Query().Get("redirect_uri")
	tmpl.Execute(w, map[string]string{"redirect_uri": redirectURI})
}

// LoginHandler handles the login form submission
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.FormValue("redirect_uri")

	var login LoginRequest
	login.Username = r.FormValue("username")
	login.Password = r.FormValue("password")

	success := AuthenticateUser(login.Username, login.Password)
	if !success {
		tmpl, _ := template.ParseFiles("templates/login.html")
		tmpl.Execute(w, map[string]string{"error": "Invalid credentials"})
		return
	}

	sessionToken := session.CreateSession(login.Username)
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(5 * time.Minute),
		Secure:   true,
		HttpOnly: true,
	})

	http.Redirect(w, r, "/authorize?authenticated=true&redirect_uri="+redirectURI+"&username="+login.Username, http.StatusFound)
}
