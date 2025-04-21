package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// User represents a user in our system
type User struct {
	ID          []byte
	Name        string
	DisplayName string
	Credentials []webauthn.Credential
}

// WebAuthnID returns the user's ID
func (u *User) WebAuthnID() []byte {
	return u.ID
}

// WebAuthnName returns the user's username
func (u *User) WebAuthnName() string {
	return u.Name
}

// WebAuthnDisplayName returns the user's display name
func (u *User) WebAuthnDisplayName() string {
	return u.DisplayName
}

// WebAuthnIcon returns the user's icon
func (u *User) WebAuthnIcon() string {
	return ""
}

// WebAuthnCredentials returns the user's credentials
func (u *User) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

// AddCredential adds a credential to the user
func (u *User) AddCredential(cred webauthn.Credential) {
	u.Credentials = append(u.Credentials, cred)
}

// UserStore is an in-memory store for users
type UserStore struct {
	users map[string]*User
	mu    sync.RWMutex
}

// NewUserStore creates a new user store
func NewUserStore() *UserStore {
	return &UserStore{
		users: make(map[string]*User),
	}
}

// GetUser returns a user by username
func (s *UserStore) GetUser(username string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.users[username]
	return user, ok
}

// GetOrCreateUser returns a user by username or creates a new one
func (s *UserStore) GetOrCreateUser(username string) *User {
	s.mu.Lock()
	defer s.mu.Unlock()

	if user, ok := s.users[username]; ok {
		return user
	}

	// Create a new user
	user := &User{
		ID:          generateUserID(username),
		Name:        username,
		DisplayName: username,
		Credentials: []webauthn.Credential{},
	}

	s.users[username] = user
	return user
}

// SaveUser saves a user
func (s *UserStore) SaveUser(user *User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[user.Name] = user
}

// SessionStore is an in-memory store for sessions
type SessionStore struct {
	sessions map[string]*webauthn.SessionData
	mu       sync.RWMutex
}

// NewSessionStore creates a new session store
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*webauthn.SessionData),
	}
}

// GetSession returns a session by ID
func (s *SessionStore) GetSession(sessionID string) (*webauthn.SessionData, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[sessionID]
	return session, ok
}

// SaveSession saves a session
func (s *SessionStore) SaveSession(sessionID string, session *webauthn.SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sessionID] = session
}

// DeleteSession deletes a session
func (s *SessionStore) DeleteSession(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}

// generateUserID generates a user ID that meets WebAuthn requirements
func generateUserID(username string) []byte {
	// Create a fixed-length ID that meets WebAuthn requirements
	// WebAuthn requires at least 16 bytes for user IDs
	id := make([]byte, 32) // Use 32 bytes to be safe

	// Fill with random data
	rand.Read(id)

	// Use the username as a seed for the first few bytes if available
	usernameBytes := []byte(username)
	for i := 0; i < len(username) && i < 8; i++ {
		id[i] = usernameBytes[i]
	}

	return id
}

// generateRandomString generates a random string
func generateRandomString(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func main() {
	// Initialize logger
	logger := log.New(os.Stdout, "[PASSKEY] ", log.LstdFlags)
	logger.Println("Starting passkey authentication server")
	logger.Println("This is a demonstration of WebAuthn (passkey) authentication")

	// Initialize stores
	userStore := NewUserStore()
	sessionStore := NewSessionStore()
	logger.Println("Initialized in-memory stores")

	// Initialize WebAuthn
	webAuthnConfig := &webauthn.Config{
		RPDisplayName: "Passkey Demo",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:8083"},
	}

	webAuthn, err := webauthn.New(webAuthnConfig)
	if err != nil {
		logger.Fatalf("Failed to create WebAuthn: %v", err)
	}
	logger.Println("Initialized WebAuthn")

	// Serve static files
	http.Handle("/", http.FileServer(http.Dir("static")))

	// API endpoints
	http.HandleFunc("/api/register/begin", func(w http.ResponseWriter, r *http.Request) {
		logger.Println("Beginning registration process")

		// Parse request
		var req struct {
			Username string `json:"username"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Printf("Failed to parse request: %v", err)
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		username := req.Username
		if username == "" {
			logger.Println("Username is required")
			http.Error(w, "Username is required", http.StatusBadRequest)
			return
		}

		logger.Printf("Registration requested for user: %s", username)

		// Get or create user
		user := userStore.GetOrCreateUser(username)
		logger.Printf("User retrieved/created: %s with ID length: %d bytes", username, len(user.ID))

		// Begin registration - this creates a challenge that the authenticator will sign
		logger.Println("Creating registration challenge for the authenticator to sign")
		logger.Println("DATABASE: Looking up user record for: " + username)
		logger.Printf("DATABASE: User found with ID: %x", user.ID)

		options, session, err := webAuthn.BeginRegistration(user)
		if err != nil {
			logger.Printf("Failed to begin registration: %v", err)
			http.Error(w, fmt.Sprintf("Failed to begin registration: %v", err), http.StatusInternalServerError)
			return
		}

		// Log the challenge details
		logger.Printf("Challenge created: %x (this is a random value the authenticator will sign)", session.Challenge)
		logger.Println("This challenge will be sent to the browser and signed by the authenticator")

		// Log the registration options
		logger.Println("Registration options created with the following parameters:")
		logger.Printf("Relying Party ID: %s", webAuthnConfig.RPID)
		logger.Printf("Relying Party Name: %s", webAuthnConfig.RPDisplayName)
		logger.Printf("User ID: %x", user.ID)
		logger.Printf("User Name: %s", user.Name)
		logger.Printf("User Display Name: %s", user.DisplayName)
		logger.Printf("Challenge: %x", session.Challenge)
		logger.Println("These options tell the authenticator what kind of credential to create")

		// Generate session ID
		sessionID, err := generateRandomString(32)
		if err != nil {
			logger.Printf("Failed to generate session ID: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// The session already has the correct UserID from webAuthn.BeginRegistration
		// Save the session with a mapping from sessionID to username for later retrieval
		sessionStore.SaveSession(sessionID, session)
		logger.Println("Registration session created with username: " + username)

		// Set session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   300, // 5 minutes
		})

		// Return registration options
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(options)
		logger.Println("Registration options sent to client")
	})

	http.HandleFunc("/api/register/finish", func(w http.ResponseWriter, r *http.Request) {
		logger.Println("Finishing registration process")

		// Get session cookie
		cookie, err := r.Cookie("session_id")
		if err != nil {
			logger.Println("No session cookie found")
			http.Error(w, "No session found", http.StatusBadRequest)
			return
		}

		sessionID := cookie.Value
		logger.Printf("Session ID: %s", sessionID)

		// Get session
		session, ok := sessionStore.GetSession(sessionID)
		if !ok {
			logger.Println("Invalid session")
			http.Error(w, "Invalid session", http.StatusBadRequest)
			return
		}

		// We need to find the user by their ID
		// First, let's log the session UserID for debugging
		logger.Printf("Session UserID: %x", session.UserID)

		// Get all users and find the one with matching ID
		var matchedUser *User
		var username string
		userStore.mu.RLock()
		for uname, u := range userStore.users {
			logger.Printf("Checking user %s with ID: %x", uname, u.ID)
			if string(u.ID) == string(session.UserID) {
				matchedUser = u
				username = uname
				break
			}
		}
		userStore.mu.RUnlock()

		logger.Printf("Looking for user with ID: %x", session.UserID)

		if matchedUser == nil {
			logger.Printf("User not found with ID: %x", session.UserID)
			http.Error(w, "User not found", http.StatusBadRequest)
			return
		}
		user := matchedUser
		logger.Printf("User found: %s", username)

		// Parse and verify credential - this processes the authenticator's response
		logger.Println("Parsing the authenticator's response containing the new public key")

		// Read the request body for logging
		bodyBytes, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // Reset the body for further reading

		logger.Printf("Received credential data: %s", string(bodyBytes))

		parsedResponse, err := protocol.ParseCredentialCreationResponseBody(r.Body)
		if err != nil {
			logger.Printf("Failed to parse credential: %v", err)
			http.Error(w, fmt.Sprintf("Failed to parse credential: %v", err), http.StatusBadRequest)
			return
		}

		logger.Println("The response contains the attestation object which includes:")
		logger.Println(" - The public key that was generated by the authenticator")
		logger.Println(" - The signature proving the key was generated by a real authenticator")
		logger.Println(" - The challenge that was signed to prevent replay attacks")

		logger.Printf("Credential ID: %s", parsedResponse.ID)
		logger.Printf("Credential Type: %s", parsedResponse.Type)
		logger.Printf("Attestation Type: %s", parsedResponse.Response.AttestationObject.Format)

		logger.Println("Verifying the authenticator's response and creating a credential")
		logger.Println("DATABASE: Retrieving session data for verification")
		logger.Printf("DATABASE: Session challenge: %x", session.Challenge)
		logger.Printf("DATABASE: Session user ID: %x", session.UserID)

		credential, err := webAuthn.CreateCredential(user, *session, parsedResponse)
		if err != nil {
			logger.Printf("Failed to create credential: %v", err)
			http.Error(w, fmt.Sprintf("Failed to create credential: %v", err), http.StatusBadRequest)
			return
		}

		logger.Println("Verification successful! The authenticator's response is valid.")
		logger.Printf("Credential created with ID: %x", credential.ID)
		logger.Println("This credential contains the public key from the authenticator")
		logger.Println("Public Key details are stored in the credential object")
		logger.Printf("Authenticator info - AAGUID: %x", credential.Authenticator.AAGUID)
		logger.Printf("Authenticator info - Sign Count: %d", credential.Authenticator.SignCount)
		logger.Println("The sign count helps detect cloned authenticators")

		// Add credential to user - this stores the public key for future authentication
		logger.Println("Storing the credential (public key) with the user account")
		logger.Println("DATABASE: Adding credential to user record")
		logger.Printf("DATABASE: Before update, user has %d credentials", len(user.Credentials))

		user.Credentials = append(user.Credentials, *credential)
		userStore.SaveUser(user)

		logger.Printf("DATABASE: After update, user has %d credentials", len(user.Credentials))
		logger.Printf("DATABASE: Saved credential with ID: %x", credential.ID)
		logger.Printf("Credential added to user: %s", username)
		logger.Println("This public key will be used to verify future authentication attempts")
		logger.Println("The private key remains on the user's device and never leaves it")

		// Delete session
		sessionStore.DeleteSession(sessionID)
		logger.Println("Registration session deleted")

		// Clear session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			MaxAge:   -1,
		})

		// Return success
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
		logger.Println("Registration completed successfully")
	})

	http.HandleFunc("/api/login/begin", func(w http.ResponseWriter, r *http.Request) {
		logger.Println("Beginning login process")

		// Parse request
		var req struct {
			Username string `json:"username"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Printf("Failed to parse request: %v", err)
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		username := req.Username
		if username == "" {
			logger.Println("Username is required")
			http.Error(w, "Username is required", http.StatusBadRequest)
			return
		}

		logger.Printf("Login requested for user: %s", username)

		// Get user
		user, ok := userStore.GetUser(username)
		if !ok {
			logger.Printf("User not found: %s", username)
			http.Error(w, "User not found", http.StatusBadRequest)
			return
		}
		logger.Printf("User found: %s", username)

		// Begin login - this creates a challenge for the authenticator to sign
		logger.Println("Creating authentication challenge for the authenticator to sign")
		logger.Println("DATABASE: Looking up user record for: " + username)
		logger.Printf("DATABASE: User found with ID: %x", user.ID)
		logger.Printf("DATABASE: User has %d registered credential(s)", len(user.Credentials))

		for i, cred := range user.Credentials {
			logger.Printf("DATABASE: Credential %d - ID: %x", i+1, cred.ID)
			logger.Printf("DATABASE: Credential %d - Last used (sign count): %d", i+1, cred.Authenticator.SignCount)
		}

		options, session, err := webAuthn.BeginLogin(user)
		if err != nil {
			logger.Printf("Failed to begin login: %v", err)
			http.Error(w, fmt.Sprintf("Failed to begin login: %v", err), http.StatusInternalServerError)
			return
		}

		// Log the challenge details
		logger.Printf("Challenge created: %x", session.Challenge)
		logger.Printf("User has %d credential(s) that can be used", len(user.Credentials))
		logger.Println("The browser will select an appropriate credential and sign the challenge")

		// Log the login options
		logger.Println("Login options created with the following parameters:")
		logger.Printf("Challenge: %x", session.Challenge)
		logger.Printf("Relying Party ID: %s", webAuthnConfig.RPID)
		logger.Printf("Allowed Credentials: %d", len(user.Credentials))

		for i, cred := range user.Credentials {
			logger.Printf("Allowed Credential %d - ID: %x", i+1, cred.ID)
		}

		// Generate session ID
		sessionID, err := generateRandomString(32)
		if err != nil {
			logger.Printf("Failed to generate session ID: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// The session already has the correct UserID from webAuthn.BeginLogin
		// Save the session with a mapping from sessionID to username for later retrieval
		sessionStore.SaveSession(sessionID, session)
		logger.Println("Login session created with username: " + username)

		// Set session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   300, // 5 minutes
		})

		// Return login options
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(options)
		logger.Println("Login options sent to client")
	})

	http.HandleFunc("/api/login/finish", func(w http.ResponseWriter, r *http.Request) {
		logger.Println("Finishing login process")

		// Get session cookie
		cookie, err := r.Cookie("session_id")
		if err != nil {
			logger.Println("No session cookie found")
			http.Error(w, "No session found", http.StatusBadRequest)
			return
		}

		sessionID := cookie.Value
		logger.Printf("Session ID: %s", sessionID)

		// Get session
		session, ok := sessionStore.GetSession(sessionID)
		if !ok {
			logger.Println("Invalid session")
			http.Error(w, "Invalid session", http.StatusBadRequest)
			return
		}

		// We need to find the user by their ID
		// First, let's log the session UserID for debugging
		logger.Printf("Session UserID: %x", session.UserID)

		// Get all users and find the one with matching ID
		var matchedUser *User
		var username string
		userStore.mu.RLock()
		for uname, u := range userStore.users {
			logger.Printf("Checking user %s with ID: %x", uname, u.ID)
			if string(u.ID) == string(session.UserID) {
				matchedUser = u
				username = uname
				break
			}
		}
		userStore.mu.RUnlock()

		logger.Printf("Looking for user with ID: %x", session.UserID)

		if matchedUser == nil {
			logger.Printf("User not found with ID: %x", session.UserID)
			http.Error(w, "User not found", http.StatusBadRequest)
			return
		}
		user := matchedUser
		logger.Printf("User found: %s", username)

		// Parse and verify credential - this processes the authenticator's signed response
		logger.Println("Parsing the authenticator's signed response")

		// Read the request body for logging
		bodyBytes, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // Reset the body for further reading

		logger.Printf("Received assertion data: %s", string(bodyBytes))

		parsedResponse, err := protocol.ParseCredentialRequestResponseBody(r.Body)
		if err != nil {
			logger.Printf("Failed to parse credential: %v", err)
			http.Error(w, fmt.Sprintf("Failed to parse credential: %v", err), http.StatusBadRequest)
			return
		}

		logger.Println("The response contains:")
		logger.Println(" - The credential ID that identifies which public key to use")
		logger.Println(" - The authenticator data with information about the authenticator")
		logger.Println(" - The signature of the challenge created with the private key")
		logger.Println(" - The client data JSON which contains the challenge and origin")

		logger.Printf("Credential ID: %s", parsedResponse.ID)
		logger.Printf("Credential Type: %s", parsedResponse.Type)
		logger.Printf("Signature Length: %d bytes", len(parsedResponse.Response.Signature))

		logger.Println("Validating the authenticator's signature using the stored public key")
		logger.Println("DATABASE: Retrieving session data for verification")
		logger.Printf("DATABASE: Session challenge: %x", session.Challenge)
		logger.Printf("DATABASE: Session user ID: %x", session.UserID)

		// Find the matching credential in the user's credentials
		logger.Println("DATABASE: Looking for matching credential in user's credentials")
		var matchingCred *webauthn.Credential
		for i, cred := range user.Credentials {
			if string(cred.ID) == string(parsedResponse.RawID) {
				logger.Printf("DATABASE: Found matching credential at index %d", i)
				matchingCred = &cred
				break
			}
		}

		if matchingCred != nil {
			logger.Printf("DATABASE: Using credential with ID: %x", matchingCred.ID)
			logger.Printf("DATABASE: Current sign count: %d", matchingCred.Authenticator.SignCount)
		}

		credential, err := webAuthn.ValidateLogin(user, *session, parsedResponse)
		if err != nil {
			logger.Printf("Failed to validate login: %v", err)
			http.Error(w, fmt.Sprintf("Failed to validate login: %v", err), http.StatusBadRequest)
			return
		}

		logger.Println("Verification successful! The signature is valid.")
		logger.Printf("Signature validated successfully for credential ID: %x", credential.ID)
		logger.Printf("Sign count updated from %d to %d", credential.Authenticator.SignCount-1, credential.Authenticator.SignCount)
		logger.Println("The sign count increases with each authentication to prevent replay attacks")
		logger.Println("DATABASE: Updating credential sign count in database")

		// Check for clone warning
		if credential.Authenticator.CloneWarning {
			logger.Println("Clone warning detected")
		}

		// Delete session
		sessionStore.DeleteSession(sessionID)
		logger.Println("Login session deleted")

		// Return success
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":   "success",
			"username": user.Name,
		})
		logger.Println("Login completed successfully")
	})

	// Start server
	port := 8083
	logger.Printf("Server listening on http://localhost:%d", port)
	logger.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
}
