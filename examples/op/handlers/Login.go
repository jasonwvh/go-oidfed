package handlers

import (
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"net/http"
	"time"
)

var jwtKey = []byte("my_secret_key")

type Credentials struct {
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
	tmpl.Execute(w, nil)
}

// LoginHandler handles the login form submission
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	creds.Username = r.FormValue("username")
	creds.Password = r.FormValue("password")

	// Simulate user authentication (replace with real user lookup)
	storedPasswordHash, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	if creds.Username != "user" || bcrypt.CompareHashAndPassword(storedPasswordHash, []byte(creds.Password)) != nil {
		tmpl, _ := template.ParseFiles("templates/login.html")
		tmpl.Execute(w, map[string]string{"error": "Invalid credentials"})
		return
	}

	// Create JWT token
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Redirect to the /authorize endpoint with the tokenString as the authorization code
	redirectURI := r.FormValue("redirect_uri")
	http.Redirect(w, r, "/authorize?code="+tokenString+"&redirect_uri="+redirectURI, http.StatusFound)
}
