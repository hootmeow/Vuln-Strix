package auth

import (
	"net/http"
	"strings"
)

// Middleware provides HTTP middleware for authentication
type Middleware struct {
	sessions    *SessionManager
	excludePaths []string
}

// NewMiddleware creates a new auth middleware
func NewMiddleware(sessions *SessionManager, excludePaths []string) *Middleware {
	return &Middleware{
		sessions:    sessions,
		excludePaths: excludePaths,
	}
}

// Wrap wraps an http.Handler with authentication checking
func (m *Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if path should be excluded
		if m.isExcluded(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Check for session cookie
		cookie, err := r.Cookie("vs_session")
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Validate session
		session, ok := m.sessions.Get(cookie.Value)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Refresh session on each request
		m.sessions.Refresh(cookie.Value)

		// Add session to request context
		r = SetSessionContext(r, session)
		next.ServeHTTP(w, r)
	})
}

// isExcluded checks if a path should be excluded from auth
func (m *Middleware) isExcluded(path string) bool {
	for _, excluded := range m.excludePaths {
		if path == excluded {
			return true
		}
		// Handle prefix matching for paths like /static/
		if strings.HasSuffix(excluded, "/") && strings.HasPrefix(path, excluded) {
			return true
		}
	}
	return false
}

// RequireAuth is a middleware that requires authentication
func RequireAuth(sessions *SessionManager, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("vs_session")
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		session, ok := sessions.Get(cookie.Value)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		r = SetSessionContext(r, session)
		next(w, r)
	}
}

// OptionalAuth adds session to context if present but doesn't require it
func OptionalAuth(sessions *SessionManager, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("vs_session")
		if err == nil && cookie.Value != "" {
			if session, ok := sessions.Get(cookie.Value); ok {
				r = SetSessionContext(r, session)
			}
		}
		next(w, r)
	}
}
