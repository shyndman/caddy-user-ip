// package caddy_user_ip provides Caddy middleware for tracking and matching user IPs.
package caddy_user_ip

// Config holds the configuration for the UserIpTracking middleware.
type Config struct {
	// PersistPath is the file path where the user->IP mapping will be stored
	PersistPath string `json:"persist_path,omitempty"`

	// MaxIpsPerUser is the maximum number of recent distinct IPs to store for each user
	MaxIpsPerUser uint64 `json:"max_ips_per_user,omitempty"`
}
