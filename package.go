// package caddy_user_ip provides Caddy middleware for tracking and matching user IPs.
package caddy_user_ip

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(UserIpTracking{})
}

// UserIpTracking is middleware that tracks and matches user IP addresses.
type UserIpTracking struct {
	// Embed the configuration directly
	Config
}

// CaddyModule returns the Caddy module information.
func (UserIpTracking) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.user_ip_tracking",
		New: func() caddy.Module { return new(UserIpTracking) },
	}
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m *UserIpTracking) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// For now, just pass the request to the next handler
	// We'll implement the actual IP tracking logic later
	return next.ServeHTTP(w, r)
}
