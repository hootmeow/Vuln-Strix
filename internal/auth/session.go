package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

// Session represents a user session
type Session struct {
	ID        string
	User      *User
	CreatedAt time.Time
	ExpiresAt time.Time
}

// SessionManager handles in-memory session storage
type SessionManager struct {
	sessions map[string]*Session
	mu       sync.RWMutex
	ttl      time.Duration
}

// NewSessionManager creates a new session manager with the given TTL in minutes
func NewSessionManager(ttlMinutes int) *SessionManager {
	if ttlMinutes <= 0 {
		ttlMinutes = 480 // Default 8 hours
	}
	sm := &SessionManager{
		sessions: make(map[string]*Session),
		ttl:      time.Duration(ttlMinutes) * time.Minute,
	}

	// Start cleanup goroutine
	go sm.cleanup()

	return sm
}

// Create creates a new session for the user
func (sm *SessionManager) Create(user *User) string {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	id := generateSessionID()
	now := time.Now()

	sm.sessions[id] = &Session{
		ID:        id,
		User:      user,
		CreatedAt: now,
		ExpiresAt: now.Add(sm.ttl),
	}

	return id
}

// Get retrieves a session by ID
func (sm *SessionManager) Get(id string) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, ok := sm.sessions[id]
	if !ok {
		return nil, false
	}

	// Check if expired
	if time.Now().After(session.ExpiresAt) {
		return nil, false
	}

	return session, true
}

// Delete removes a session
func (sm *SessionManager) Delete(id string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	delete(sm.sessions, id)
}

// Refresh extends a session's expiration time
func (sm *SessionManager) Refresh(id string) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, ok := sm.sessions[id]
	if !ok {
		return false
	}

	session.ExpiresAt = time.Now().Add(sm.ttl)
	return true
}

// cleanup periodically removes expired sessions
func (sm *SessionManager) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		sm.mu.Lock()
		now := time.Now()
		for id, session := range sm.sessions {
			if now.After(session.ExpiresAt) {
				delete(sm.sessions, id)
			}
		}
		sm.mu.Unlock()
	}
}

// generateSessionID creates a cryptographically secure session ID
func generateSessionID() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based ID (less secure, but better than panic)
		return hex.EncodeToString([]byte(time.Now().String()))
	}
	return hex.EncodeToString(bytes)
}

// Context key for session
type contextKey string

const sessionContextKey contextKey = "session"

// SetSessionContext adds the session to the request context
func SetSessionContext(r *http.Request, session *Session) *http.Request {
	ctx := context.WithValue(r.Context(), sessionContextKey, session)
	return r.WithContext(ctx)
}

// GetSessionContext retrieves the session from the request context
func GetSessionContext(r *http.Request) *Session {
	session, _ := r.Context().Value(sessionContextKey).(*Session)
	return session
}
