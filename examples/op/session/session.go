package session

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

type Session struct {
	Username  string
	ExpiresAt time.Time
}

var sessions = make(map[string]Session)
var mu sync.Mutex

// GenerateAuthCode generates a secure authorization code
func GenerateAuthCode() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// CreateSession creates a new session for the given username
func CreateSession(username string) string {
	mu.Lock()
	defer mu.Unlock()
	sessionToken := GenerateAuthCode() // Generate a unique session token
	sessions[sessionToken] = Session{
		Username:  username,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	return sessionToken
}

// IsValidSession checks if the session token is valid
func IsValidSession(token string) bool {
	mu.Lock()
	defer mu.Unlock()
	session, exists := sessions[token]
	return exists && time.Now().Before(session.ExpiresAt)
}

// GetUsernameFromSession retrieves the username associated with the session token
func GetUsernameFromSession(token string) string {
	mu.Lock()
	defer mu.Unlock()
	return sessions[token].Username
}
