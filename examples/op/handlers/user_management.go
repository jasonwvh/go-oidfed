package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"golang.org/x/crypto/argon2"
	"net/http"
	"sync"
)

type Encryption string

const (
	PLAIN  Encryption = "plain"
	SHA256 Encryption = "sha256"
	SHA512 Encryption = "sha512"
	ARGON2 Encryption = "argon2"
)

type Password struct {
	Value      string     `json:"password"`
	Salt       string     `json:"salt"`
	Encryption Encryption `json:"encryption"`
}
type Credentials struct {
	Username string   `json:"username"`
	Password Password `json:"password"`
}

var (
	users = map[string]Password{
		"user1": {
			Value:      "password1",
			Salt:       "salt1",
			Encryption: PLAIN,
		},
		"user2": {
			Value:      "password2",
			Salt:       "salt2",
			Encryption: PLAIN,
		},
		"user3": {
			Value:      "password3",
			Salt:       "salt3",
			Encryption: PLAIN,
		},
	} // map to store user credentials
	usersMutex sync.RWMutex // mutex to handle concurrent access
)

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func RegisterUser(w http.ResponseWriter, r *http.Request) {
	var user RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	salt, err := generateSalt()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	hashingAlgorithm := ARGON2
	hashedPassword := hashPassword(user.Password, salt, hashingAlgorithm)

	usersMutex.Lock()
	defer usersMutex.Unlock()
	users[user.Username] = Password{
		Value:      hashedPassword,
		Salt:       salt,
		Encryption: hashingAlgorithm,
	}

	w.WriteHeader(http.StatusCreated)
}

func AuthenticateUser(username, password string) bool {
	usersMutex.RLock()
	defer usersMutex.RUnlock()
	
	if storedPassword, ok := users[username]; ok {
		hashedPassword := hashPassword(password, storedPassword.Salt, storedPassword.Encryption)
		if hashedPassword == "" {
			return false
		}

		return hashedPassword == storedPassword.Value
	}
	return false
}

func generateSalt() (string, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(salt), nil
}

func hashPassword(password, salt string, encryption Encryption) string {
	switch encryption {
	case PLAIN:
		return password
	case SHA256:
		hash := sha256.Sum256([]byte(password + salt))
		return base64.StdEncoding.EncodeToString(hash[:])
	case SHA512:
		hash := sha512.Sum512([]byte(password + salt))
		return base64.StdEncoding.EncodeToString(hash[:])
	case ARGON2:
		saltBytes, _ := base64.StdEncoding.DecodeString(salt)
		hash := argon2.IDKey([]byte(password), saltBytes, 1, 64*1024, 4, 32)
		return base64.StdEncoding.EncodeToString(hash)
	default:
		return ""
	}
}
