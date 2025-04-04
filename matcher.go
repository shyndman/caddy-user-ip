// package caddy_user_ip provides Caddy middleware for tracking and matching user IPs.
package caddy_user_ip

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
)

// UserIPMatcher is a request matcher that matches requests based on whether
// the client IP address is in the list of tracked user IPs.
type UserIPMatcher struct {
	// Logger for the matcher
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (UserIPMatcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.user_ip",
		New: func() caddy.Module { return new(UserIPMatcher) },
	}
}

// Provision sets up the matcher.
func (m *UserIPMatcher) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	return nil
}

// Match returns true if the request's client IP address is in the list of tracked user IPs.
func (m UserIPMatcher) Match(r *http.Request) bool {
	match, _ := m.MatchWithError(r)
	return match
}

// MatchWithError returns true if the request's client IP address is in the list of tracked user IPs.
func (m UserIPMatcher) MatchWithError(r *http.Request) (bool, error) {
	// Extract the client IP address
	clientIP := getClientIP(r)

	// Check if we have a global storage reference
	if globalStorage == nil {
		m.logger.Debug("No global storage available for matching")
		return false, nil
	}

	// Check if the IP is in the storage
	hasIP := globalStorage.HasIP(clientIP)

	// Dump the contents of the storage for debugging
	globalStorage.mu.RLock()
	var users []string
	for user := range globalStorage.userData {
		users = append(users, user)
	}
	var ips []string
	for ip := range globalStorage.ipToUsers {
		ips = append(ips, ip)
	}
	globalStorage.mu.RUnlock()

	m.logger.Debug("Matching client IP against known user IPs",
		zap.String("ip", clientIP),
		zap.Bool("match", hasIP),
		zap.Strings("known_users", users),
		zap.Strings("known_ips", ips))

	return hasIP, nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *UserIPMatcher) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		// No arguments needed for this matcher
		if d.NextArg() {
			return d.ArgErr()
		}

		// No block support
		if d.NextBlock(0) {
			return d.Err("user_ip matcher does not support blocks")
		}
	}
	return nil
}
