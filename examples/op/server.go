package main

import (
	"fmt"
	"github.com/zachmann/go-oidfed/examples/op/config"
	"github.com/zachmann/go-oidfed/examples/op/handlers"
	"log"
	"net/http"
)

func initServer() {
	http.HandleFunc("/.well-known/openid-federation", handlers.HandleEntityConfiguration)
	http.HandleFunc("/.well-known/openid-configuration", handlers.HandleOIDCConfiguration)
	http.HandleFunc("/authorize", handlers.HandleAuthorize)
	http.HandleFunc("/submit", handlers.LoginHandler)
	http.HandleFunc("/login", handlers.LoginPageHandler)
	http.HandleFunc("/token", handlers.HandleToken)
	http.HandleFunc("/userinfo", handlers.HandleUserInfo)
	http.HandleFunc("/jwks", handlers.HandleJWKS)
	http.HandleFunc("/logout", handlers.HandleLogout)
	http.HandleFunc("/register", handlers.RegisterUser)
	http.HandleFunc("/enroll", func(w http.ResponseWriter, r *http.Request) {
		http.Get("http://localhost:8765/enroll?sub=http://localhost:4444")
	})

	fmt.Printf("Serving on %s\n", config.Conf.ServerAddr)
	if err := http.ListenAndServe(config.Conf.ServerAddr, nil); err != nil {
		log.Fatal(err)
	}
}
