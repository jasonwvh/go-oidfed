package handlers

import (
	"encoding/json"
	"net/http"
)

func HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	// Handle the user info request
	// This is a simplified example, you need to implement the full logic
	userInfo := map[string]string{
		"sub":   "1234567890",
		"name":  "John Doe",
		"email": "john.doe@example.com",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}
