// package caddy_user_ip provides Caddy middleware for tracking and matching user IPs.
package caddy_user_ip

import (
	"sync"

	"github.com/caddyserver/caddy/v2"
)

var (
	storageOnce   sync.Once
	globalStorage *UserIPStorage
)

// getStorage returns the singleton UserIPStorage instance, creating it if necessary.
func getStorage() *UserIPStorage {
	storageOnce.Do(func() {
		globalStorage = &UserIPStorage{
			userData:  make(map[string]*UserData),
			ipToUsers: make(map[string]map[string]struct{}),
			mu:        sync.RWMutex{},
		}
	})
	return globalStorage
}

// resetStorage resets the singleton instance for testing purposes.
func resetStorage() {
	globalStorage = nil
	storageOnce = sync.Once{}
}

func init() {
	// Register the middleware module
	caddy.RegisterModule(&UserIpTracking{})

	// Register the matcher module
	caddy.RegisterModule(UserIPMatcher{})
}

