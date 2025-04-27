// package caddy_user_ip provides Caddy middleware for tracking and matching user IPs.
package caddy_user_ip

// Adding a comment to trigger re-analysis

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync" // Added sync import
	"time" // Keep time for time.Duration
	"github.com/jonboulle/clockwork"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

var testClockInject clockwork.Clock

// UserIpTracking is middleware that tracks and matches user IP addresses.
type UserIpTracking struct {
	// Embed the configuration directly
	Config

	// Logger for the middleware
	logger *zap.Logger

	// Storage for user IPs
	storage *UserIPStorage

	// clock provides access to time functions via the clockwork interface
	clock clockwork.Clock

	// Fields for periodic persistence
	persistInterval time.Duration
	stopPersister   chan struct{}
	persisterWg     sync.WaitGroup
}

// CaddyModule returns the Caddy module information.
func (*UserIpTracking) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.user_ip_tracking",
		New: func() caddy.Module { return new(UserIpTracking) },
	}
}

// Provision sets up the middleware.
func (m *UserIpTracking) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	if testClockInject != nil {
		m.clock = testClockInject
	} else {
		m.clock = clockwork.NewRealClock() // Instantiate the real clock from the library
	}

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
	m.storage = NewUserIPStorage(m.PersistPath, m.MaxIpsPerUser, m.UserDataTTL, m.clock, m.logger) // Pass the logger

	// Set the global storage reference for the matcher to use
	globalStorage = m.storage

	// Load existing data from disk
	if err := m.storage.LoadFromDisk(); err != nil {
		m.logger.Error("Failed to load user IP data from disk",
			zap.String("path", m.PersistPath),
			zap.Error(err))
		return fmt.Errorf("loading user IP data: %v", err)
	}

	m.logger.Info("Loaded user IP data from disk",
		zap.String("path", m.PersistPath))

	// Initialize and start the periodic persister
	m.persistInterval = 5 * time.Minute // Or read from config if made configurable
	m.stopPersister = make(chan struct{})
	m.persisterWg.Add(1)
	go m.runPeriodicPersister() // This will now use m.clock

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

	// Dump the contents of the storage for debugging
	m.storage.mu.RLock()
	var users []string
	for user := range m.storage.userData {
		users = append(users, user)
	}
	var ips []string
	for ip := range m.storage.ipToUsers {
		ips = append(ips, ip)
	}
	m.storage.mu.RUnlock()

	// Log the IP tracking
	m.logger.Debug("Tracked user IP",
		zap.String("email", email),
		zap.String("ip", clientIP),
		zap.Bool("new_ip", ipAdded),
		zap.Strings("known_users", users),
		zap.Strings("known_ips", ips))

	// If the IP was newly added, persist the data (respecting the dirty flag)
	if ipAdded {
		go func() {
			if err := m.storage.PersistToDisk(false); err != nil {
				m.logger.Error("Failed to persist user IP data (new IP)",
					zap.String("path", m.PersistPath),
					zap.Error(err))
			} else {
				m.logger.Debug("Persisted user IP data (new IP)",
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

// Interface guards
var (
	_ caddy.Provisioner           = (*UserIpTracking)(nil)
	_ caddyhttp.MiddlewareHandler = (*UserIpTracking)(nil)
	_ caddy.CleanerUpper          = (*UserIpTracking)(nil) // Implement CleanerUpper
)

// Cleanup is called when the module is unloaded.
func (m *UserIpTracking) Cleanup() error {
	m.logger.Info("Shutting down periodic persister")
	close(m.stopPersister) // Signal the goroutine to stop
	m.persisterWg.Wait()   // Wait for the goroutine to finish
	m.logger.Info("Periodic persister stopped")

	// Perform final persistence on shutdown
	m.logger.Info("Performing final persistence on shutdown")
	if err := m.storage.PersistToDisk(true); err != nil {
		m.logger.Error("Failed to perform final persistence on shutdown",
			zap.String("path", m.PersistPath),
			zap.Error(err))
		return fmt.Errorf("final persistence on shutdown: %v", err)
	}
	m.logger.Info("Final persistence on shutdown complete")

	return nil
}

// runPeriodicPersister runs a goroutine to periodically persist data.
func (m *UserIpTracking) runPeriodicPersister() {
	defer m.persisterWg.Done()

	ticker := m.clock.NewTicker(m.persistInterval) // Use the clockwork interface
	defer ticker.Stop()

	m.logger.Info("Periodic persister started", zap.Duration("interval", m.persistInterval))

	for {
		select {
		case <-ticker.Chan(): // Use Chan() method from clockwork.Ticker interface
			m.logger.Debug("Periodic persistence triggered")
			if err := m.storage.PersistToDisk(true); err != nil { // Force persistence
				m.logger.Error("Failed during periodic persistence",
					zap.String("path", m.PersistPath),
					zap.Error(err))
			} else {
				m.logger.Debug("Periodic persistence complete")
			}
		case <-m.stopPersister:
			m.logger.Debug("Stop signal received, periodic persister exiting")
			return
		}
	}
}
