// package caddy_user_ip provides Caddy middleware for tracking and matching user IPs.
package caddy_user_ip

import (
	"github.com/caddyserver/caddy/v2"
)

// Global variable to store a reference to the storage
// This is a bit of a hack, but it allows the matcher to access the storage
// without having to pass it explicitly
var globalStorage *UserIPStorage

func init() {
	// Register the middleware module
	caddy.RegisterModule(&UserIpTracking{})

	// Register the matcher module
	caddy.RegisterModule(UserIPMatcher{})
}
