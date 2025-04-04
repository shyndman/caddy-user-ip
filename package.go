// package caddy_user_ip provides Caddy middleware for tracking and matching user IPs.
package caddy_user_ip

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(UserIpTracking{})
}

// UserIpTracking is middleware that tracks and matches user IP addresses.
type UserIpTracking struct {
	// Embed the configuration directly
	Config

	// Logger for the middleware
	logger *zap.Logger

	// Storage for user IPs
	storage *UserIPStorage
}

// CaddyModule returns the Caddy module information.
func (UserIpTracking) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.user_ip_tracking",
		New: func() caddy.Module { return new(UserIpTracking) },
	}
}

// Provision sets up the middleware.
func (m *UserIpTracking) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)

	// Log the configuration values to verify they were parsed correctly
	m.logger.Info("UserIpTracking middleware provisioned",
		zap.String("persist_path", m.PersistPath),
		zap.Uint64("max_ips_per_user", m.MaxIpsPerUser),
		zap.Uint64("user_data_ttl", m.UserDataTTL))

	// Validate configuration
	if m.PersistPath == "" {
		return fmt.Errorf("persist_path is required")
	}

	if m.MaxIpsPerUser <= 0 {
		return fmt.Errorf("max_ips_per_user must be greater than 0")
	}

	// Initialize the storage
	m.storage = NewUserIPStorage(m.PersistPath, m.MaxIpsPerUser, m.UserDataTTL)

	// Load existing data from disk
	if err := m.storage.LoadFromDisk(); err != nil {
		m.logger.Error("Failed to load user IP data from disk",
			zap.String("path", m.PersistPath),
			zap.Error(err))
		return fmt.Errorf("loading user IP data: %v", err)
	}

	m.logger.Info("Loaded user IP data from disk",
		zap.String("path", m.PersistPath))

	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m *UserIpTracking) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Check for the X-Token-User-Email header
	email := r.Header.Get("X-Token-User-Email")
	if email == "" {
		// No authenticated user, just pass through
		m.logger.Debug("No X-Token-User-Email header, skipping IP tracking")
		return next.ServeHTTP(w, r)
	}

	// Extract the client IP address
	clientIP := getClientIP(r)

	// Add the IP to the user's list
	ipAdded := m.storage.AddUserIP(email, clientIP)

	// Log the IP tracking
	m.logger.Debug("Tracked user IP",
		zap.String("email", email),
		zap.String("ip", clientIP),
		zap.Bool("new_ip", ipAdded))

	// If the IP was newly added, persist the data
	if ipAdded {
		go func() {
			if err := m.storage.PersistToDisk(); err != nil {
				m.logger.Error("Failed to persist user IP data",
					zap.String("path", m.PersistPath),
					zap.Error(err))
			} else {
				m.logger.Debug("Persisted user IP data",
					zap.String("path", m.PersistPath))
			}
		}()
	}

	// Continue with the request
	return next.ServeHTTP(w, r)
}

// getClientIP extracts the client IP address from the request.
func getClientIP(r *http.Request) string {
	// Check for X-Forwarded-For header first
	forwardedFor := r.Header.Get("X-Forwarded-For")
	if forwardedFor != "" {
		// X-Forwarded-For can contain multiple IPs, use the first one
		forwardedIPs := strings.Split(forwardedFor, ",")
		return strings.TrimSpace(forwardedIPs[0])
	}

	// Check for X-Real-IP header
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If there's an error, just return the RemoteAddr as is
		return r.RemoteAddr
	}

	return ip
}
