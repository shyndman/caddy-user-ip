// package caddy_user_ip provides Caddy middleware for tracking and matching user IPs.
package caddy_user_ip

// Config holds the configuration for the UserIpTracking middleware.
type Config struct {
	// PersistPath is the file path where the user->IP mapping will be stored
	PersistPath string `json:"persist_path,omitempty"`

	// MaxIpsPerUser is the maximum number of recent distinct IPs to store for each user
	MaxIpsPerUser uint64 `json:"max_ips_per_user,omitempty"`

	// UserDataTTL is the time-to-live for user data in seconds
	// After this period of inactivity, a user's data will be removed
	// A value of 0 means no expiration
	UserDataTTL uint64 `json:"user_data_ttl,omitempty"`
}
