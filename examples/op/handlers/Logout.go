package handlers

import "net/http"

func HandleLogout(w http.ResponseWriter, r *http.Request) {
	// Handle the logout request
	// This is a simplified example, you need to implement the full logic
	http.Redirect(w, r, "/", http.StatusFound)
}
