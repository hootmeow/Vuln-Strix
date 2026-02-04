package auth

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// User represents an authenticated user
type User struct {
	Username    string
	DisplayName string
	Email       string
	DN          string
}

// LDAPAuthenticator handles LDAP/Active Directory authentication
type LDAPAuthenticator struct {
	server       string
	port         int
	useTLS       bool
	baseDN       string
	bindUser     string
	bindPassword string
	userFilter   string
}

// NewLDAPAuthenticator creates a new LDAP authenticator
func NewLDAPAuthenticator(server string, port int, useTLS bool, baseDN, bindUser, bindPassword, userFilter string) *LDAPAuthenticator {
	if userFilter == "" {
		userFilter = "(sAMAccountName=%s)"
	}
	if port == 0 {
		if useTLS {
			port = 636
		} else {
			port = 389
		}
	}
	return &LDAPAuthenticator{
		server:       server,
		port:         port,
		useTLS:       useTLS,
		baseDN:       baseDN,
		bindUser:     bindUser,
		bindPassword: bindPassword,
		userFilter:   userFilter,
	}
}

// Authenticate validates user credentials against LDAP
func (a *LDAPAuthenticator) Authenticate(username, password string) (*User, error) {
	// Connect to LDAP server
	conn, err := a.connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}
	defer conn.Close()

	// First bind with service account to search for user
	if err := conn.Bind(a.bindUser, a.bindPassword); err != nil {
		return nil, fmt.Errorf("service account bind failed: %w", err)
	}

	// Search for user DN
	filter := fmt.Sprintf(a.userFilter, ldap.EscapeFilter(username))
	searchRequest := ldap.NewSearchRequest(
		a.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, // Size limit
		0, // Time limit
		false,
		filter,
		[]string{"dn", "cn", "displayName", "mail", "sAMAccountName"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("user search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("user not found")
	}

	if len(result.Entries) > 1 {
		return nil, fmt.Errorf("multiple users found")
	}

	entry := result.Entries[0]
	userDN := entry.DN

	// Attempt to bind as the user to verify password
	if err := conn.Bind(userDN, password); err != nil {
		return nil, fmt.Errorf("authentication failed")
	}

	// Build user object
	user := &User{
		Username:    username,
		DisplayName: entry.GetAttributeValue("displayName"),
		Email:       entry.GetAttributeValue("mail"),
		DN:          userDN,
	}

	if user.DisplayName == "" {
		user.DisplayName = entry.GetAttributeValue("cn")
	}
	if user.DisplayName == "" {
		user.DisplayName = username
	}

	return user, nil
}

// connect establishes a connection to the LDAP server
func (a *LDAPAuthenticator) connect() (*ldap.Conn, error) {
	address := fmt.Sprintf("%s:%d", a.server, a.port)

	if a.useTLS {
		// LDAPS connection
		tlsConfig := &tls.Config{
			ServerName: a.server,
			MinVersion: tls.VersionTLS12,
		}
		return ldap.DialTLS("tcp", address, tlsConfig)
	}

	// Plain LDAP connection
	return ldap.Dial("tcp", address)
}

// TestConnection tests the LDAP connection with the service account
func (a *LDAPAuthenticator) TestConnection() error {
	conn, err := a.connect()
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(a.bindUser, a.bindPassword); err != nil {
		return fmt.Errorf("service account bind failed: %w", err)
	}

	return nil
}

// GetUserGroups retrieves the groups a user belongs to
func (a *LDAPAuthenticator) GetUserGroups(userDN string) ([]string, error) {
	conn, err := a.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.Bind(a.bindUser, a.bindPassword); err != nil {
		return nil, err
	}

	// Search for user's memberOf attribute
	searchRequest := ldap.NewSearchRequest(
		userDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"memberOf"},
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	if len(result.Entries) == 0 {
		return nil, nil
	}

	groups := result.Entries[0].GetAttributeValues("memberOf")

	// Extract CN from group DNs
	var groupNames []string
	for _, g := range groups {
		parts := strings.Split(g, ",")
		if len(parts) > 0 && strings.HasPrefix(parts[0], "CN=") {
			groupNames = append(groupNames, strings.TrimPrefix(parts[0], "CN="))
		}
	}

	return groupNames, nil
}
