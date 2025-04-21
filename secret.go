package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"
)

// Secret represents a secret with its ID, salt, and PRF output
type Secret struct {
	ID        string // base64url (16 bytes)
	Salt      string // base64url (32 bytes)
	PRFOutput string // base64url (32 bytes) – filled in after Get PRF
}

// SecretStore is an in-memory store for secrets
type SecretStore struct {
	secretsByUser map[string][]Secret // map[username][]Secret
	mu            sync.RWMutex
}

// NewSecretStore creates a new secret store
func NewSecretStore() *SecretStore {
	return &SecretStore{
		secretsByUser: make(map[string][]Secret),
	}
}

// AddSecret adds a new secret for a user
func (s *SecretStore) AddSecret(username string, secret Secret) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.secretsByUser[username]; !ok {
		s.secretsByUser[username] = []Secret{}
	}

	s.secretsByUser[username] = append(s.secretsByUser[username], secret)
}

// GetSecretByID returns a secret by its ID for a specific user
func (s *SecretStore) GetSecretByID(username, secretID string) (*Secret, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	secrets, ok := s.secretsByUser[username]
	if !ok {
		return nil, false
	}

	for i, secret := range secrets {
		if secret.ID == secretID {
			return &secrets[i], true
		}
	}

	return nil, false
}

// UpdateSecretPRFOutput updates the PRF output for a secret
func (s *SecretStore) UpdateSecretPRFOutput(username, secretID, prfOutput string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	secrets, ok := s.secretsByUser[username]
	if !ok {
		return false
	}

	for i, secret := range secrets {
		if secret.ID == secretID {
			secrets[i].PRFOutput = prfOutput
			s.secretsByUser[username] = secrets
			return true
		}
	}

	return false
}

// GenerateRandomBytes generates random bytes of the specified length
func GenerateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// RegisterSecretHandlers registers the secret-related HTTP handlers
func RegisterSecretHandlers(secretStore *SecretStore, userStore *UserStore, sessionStore *SessionStore, webAuthn *webauthn.WebAuthn, logger *log.Logger) {
	// Handler for adding a new secret
	http.HandleFunc("/api/secret/add", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get username from session cookie
		cookie, err := r.Cookie("session_id")
		if err != nil {
			logger.Printf("No session cookie found: %v", err)
			http.Error(w, "Not logged in", http.StatusUnauthorized)
			return
		}

		// Get session data
		sessionID := cookie.Value
		session, ok := sessionStore.GetSession(sessionID)
		if !ok {
			logger.Printf("Session not found: %s", sessionID)
			http.Error(w, "Session not found", http.StatusUnauthorized)
			return
		}

		// Get user by ID
		_, username, ok := userStore.GetUserByID(session.UserID)
		if !ok {
			logger.Printf("User not found with ID: %x", session.UserID)
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		logger.Printf("Adding secret for user: %s", username)

		// Generate random secretID (16 bytes)
		secretIDBytes, err := GenerateRandomBytes(16)
		if err != nil {
			logger.Printf("Failed to generate secretID: %v", err)
			http.Error(w, "Failed to generate secretID", http.StatusInternalServerError)
			return
		}
		secretID := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(secretIDBytes)

		// Generate random salt (32 bytes)
		saltBytes, err := GenerateRandomBytes(32)
		if err != nil {
			logger.Printf("Failed to generate salt: %v", err)
			http.Error(w, "Failed to generate salt", http.StatusInternalServerError)
			return
		}
		salt := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(saltBytes)

		// Create and store the secret
		secret := Secret{
			ID:   secretID,
			Salt: salt,
		}

		secretStore.AddSecret(username, secret)
		logger.Printf("Secret added for user %s: ID=%s, Salt=%s", username, secretID, salt)

		// Return the secret ID and salt
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"secretID": secretID,
			"salt":     salt,
		})
	})

	// Handler for getting PRF assertion options
	http.HandleFunc("/api/prf/assertionOptions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse request
		var request struct {
			SecretID string `json:"secretID"`
		}

		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			logger.Printf("Failed to parse request: %v", err)
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		// Get username from session cookie
		cookie, err := r.Cookie("session_id")
		if err != nil {
			logger.Printf("No session cookie found: %v", err)
			http.Error(w, "Not logged in", http.StatusUnauthorized)
			return
		}

		// Get session data
		sessionID := cookie.Value
		session, ok := sessionStore.GetSession(sessionID)
		if !ok {
			logger.Printf("Session not found: %s", sessionID)
			http.Error(w, "Session not found", http.StatusUnauthorized)
			return
		}

		// Get user by ID
		user, username, ok := userStore.GetUserByID(session.UserID)
		if !ok {
			logger.Printf("User not found with ID: %x", session.UserID)
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		logger.Printf("Getting PRF assertion options for user: %s, secretID: %s", username, request.SecretID)

		// User is already retrieved above

		// Get secret
		secret, ok := secretStore.GetSecretByID(username, request.SecretID)
		if !ok {
			logger.Printf("Secret not found: %s", request.SecretID)
			http.Error(w, "Secret not found", http.StatusNotFound)
			return
		}

		// Create a session ID
		assertionSessionID, err := generateRandomString(32)
		if err != nil {
			logger.Printf("Failed to generate session ID: %v", err)
			http.Error(w, "Failed to generate session ID", http.StatusInternalServerError)
			return
		}

		// Begin assertion
		options, session, err := webAuthn.BeginLogin(user)
		if err != nil {
			logger.Printf("Failed to begin login: %v", err)
			http.Error(w, fmt.Sprintf("Failed to begin login: %v", err), http.StatusInternalServerError)
			return
		}

		// Add PRF extension
		// Convert the protocol.CredentialAssertion to a map to add the extension
		optionsMap := map[string]interface{}{
			"publicKey": map[string]interface{}{
				"challenge":        options.Response.Challenge,
				"timeout":          options.Response.Timeout,
				"rpId":             options.Response.RelyingPartyID,
				"allowCredentials": options.Response.AllowedCredentials,
				"userVerification": options.Response.UserVerification,
				"extensions": map[string]interface{}{
					"prf": map[string]interface{}{
						"eval": map[string]interface{}{
							"first": secret.Salt, // The salt is already base64url encoded
						},
					},
				},
			},
		}

		// Store session
		sessionStore.SaveSession(assertionSessionID, session)
		logger.Printf("PRF assertion session created: %s", assertionSessionID)

		// Set session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "assertion_session",
			Value:    assertionSessionID,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})

		// Return options
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(optionsMap)

		logger.Printf("PRF assertion options sent: %+v", options)
	})

	// Handler for storing PRF result
	http.HandleFunc("/api/secret/storeResult", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse request
		var request struct {
			SecretID  string `json:"secretID"`
			PRFOutput string `json:"prfOutput"`
		}

		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			logger.Printf("Failed to parse request: %v", err)
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		// Get username from session cookie
		cookie, err := r.Cookie("session_id")
		if err != nil {
			logger.Printf("No session cookie found: %v", err)
			http.Error(w, "Not logged in", http.StatusUnauthorized)
			return
		}

		// Get session data
		sessionID := cookie.Value
		session, ok := sessionStore.GetSession(sessionID)
		if !ok {
			logger.Printf("Session not found: %s", sessionID)
			http.Error(w, "Session not found", http.StatusUnauthorized)
			return
		}

		// Get user by ID
		_, username, ok := userStore.GetUserByID(session.UserID)
		if !ok {
			logger.Printf("User not found with ID: %x", session.UserID)
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		logger.Printf("Storing PRF result for user: %s, secretID: %s", username, request.SecretID)

		// Verify PRF output length (should be 32 bytes when decoded)
		prfOutputBytes, err := base64.StdEncoding.DecodeString(request.PRFOutput)
		if err != nil || len(prfOutputBytes) != 32 {
			logger.Printf("Invalid PRF output: %v, length: %d", err, len(prfOutputBytes))
			http.Error(w, "Invalid PRF output", http.StatusBadRequest)
			return
		}

		// Convert to URL-safe base64 without padding
		prfOutputURLSafe := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(prfOutputBytes)

		// Update secret
		if ok := secretStore.UpdateSecretPRFOutput(username, request.SecretID, prfOutputURLSafe); !ok {
			logger.Printf("Failed to update secret PRF output")
			http.Error(w, "Failed to update secret", http.StatusInternalServerError)
			return
		}

		logger.Printf("PRF output stored for user %s, secretID: %s", username, request.SecretID)

		// Return success
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "success",
		})
	})
}
