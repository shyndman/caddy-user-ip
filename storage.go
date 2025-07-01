// package caddy_user_ip provides Caddy middleware for tracking and matching user IPs.
package caddy_user_ip

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/jonboulle/clockwork"
	"go.uber.org/zap" // Import the zap logging library
)

// IPData represents an IP address with its timestamp information
type IPData struct {
	// The IP address
	IP string `json:"ip"`

	// Unix timestamp when this IP was last seen (seconds)
	LastSeen int64 `json:"last_seen"`

	// ISO8601 datetime string for debug purposes (only set when debug logging enabled)
	LastSeenISO string `json:"last_seen_iso,omitempty"`
}

// UserData represents the data stored for each user
type UserData struct {
	// List of historical IPs with timestamps (newest first)
	IPs []IPData `json:"ips"`

	// Timestamp of last activity (Unix timestamp in seconds) - kept for backward compatibility during migration
	LastSeen int64 `json:"last_seen,omitempty"`
}

// legacyUserData represents the old format for migration purposes
type legacyUserData struct {
	IPs      []string `json:"ips"`
	LastSeen int64    `json:"last_seen"`
}

// UserIPStorage manages the storage of user IP addresses.
type UserIPStorage struct {
	// Maps user emails to their data
	userData map[string]*UserData

	// Maps IP addresses to a set of users who have used that IP
	// This allows for efficient lookups when matching IPs
	ipToUsers map[string]map[string]struct{}

	// Maximum number of IPs to store per user
	maxIPsPerUser uint64

	// Time-to-live for user data in seconds (0 means no expiration)
	userDataTTL uint64

	// Path to persist the data
	persistPath string

	// Mutex for thread-safe access
	mu sync.RWMutex

	// Flag to track if data has changed since last persist
	dirty bool

	// clock provides access to time functions via the clockwork interface
	clock clockwork.Clock

	// Logger for the storage
	logger *zap.Logger

	// Flag to enable debug logging with ISO8601 timestamps
	debugLogging bool

	// Flag to indicate if storage has been configured
	configured bool
}

// Configure sets up the storage instance. It only allows configuration once.
// Returns true if the configuration was applied, false if it was already configured.
func (s *UserIPStorage) Configure(persistPath string, maxIPsPerUser uint64, userDataTTL uint64,
	clock clockwork.Clock, logger *zap.Logger) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.configured {
		return false
	}

	s.persistPath = persistPath
	s.maxIPsPerUser = maxIPsPerUser
	s.userDataTTL = userDataTTL
	s.clock = clock
	s.logger = logger
	s.debugLogging = logger.Level() == zap.DebugLevel
	s.configured = true
	s.dirty = false // Initialize dirty flag
	s.logger.Debug("UserIPStorage configured and initialized with dirty=false")

	return true
}


// AddUserIP adds an IP address for a user, maintaining the FIFO limit.
// Returns true if the IP was newly added (not already in the user's list).
func (s *UserIPStorage) AddUserIP(email, ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clock.Now().Unix()
	nowISO := ""
	if s.debugLogging {
		nowISO = s.clock.Now().Format("2006-01-02T15:04:05-07:00")
	}

	// Get or create user data
	userData, exists := s.userData[email]
	if !exists {
		// Create new user data
		userData = &UserData{
			IPs: []IPData{},
		}
		s.userData[email] = userData
		s.logger.Info("Created new user entry", zap.String("user", email), zap.String("ip", ip))
	} else {
		// Check if this user already has this IP in their list
		foundIndex := -1
		for i, ipData := range userData.IPs {
			if ipData.IP == ip {
				foundIndex = i
				break
			}
		}

		if foundIndex != -1 {
			// IP already exists for this user, update timestamp and move to front if needed
			ipData := userData.IPs[foundIndex]
			ipData.LastSeen = now
			if s.debugLogging {
				ipData.LastSeenISO = nowISO
			}

			if foundIndex > 0 {
				// IP is not the most recent, move it to the front (MRU)
				// Remove the IP from its current position
				userData.IPs = append(userData.IPs[:foundIndex], userData.IPs[foundIndex+1:]...)
				// Prepend the IP to the front
				userData.IPs = append([]IPData{ipData}, userData.IPs...)

				s.logger.Debug("Moved existing IP to front (MRU)", zap.String("user", email), zap.String("ip", ip))
				// Mark as dirty and trigger immediate write
				s.dirty = true
				go s.writeImmediately()
			} else {
				// Update the first entry in place (timestamp changed)
				userData.IPs[0] = ipData
				// Mark as dirty and trigger immediate write since timestamp updates are important
				s.dirty = true
				go s.writeImmediately()
			}
			return false // No new IP was added
		}
	}

	// Create new IP data entry
	newIPData := IPData{
		IP:       ip,
		LastSeen: now,
	}
	if s.debugLogging {
		newIPData.LastSeenISO = nowISO
	}

	// Add IP to user's list (prepend to maintain newest-first order)
	userData.IPs = append([]IPData{newIPData}, userData.IPs...)

	// Trim list if it exceeds the maximum and log evicted IP
	if uint64(len(userData.IPs)) > s.maxIPsPerUser {
		// Get the IP that's being removed (last in the list)
		removedIPData := userData.IPs[s.maxIPsPerUser]
		removedIP := removedIPData.IP

		// Log the eviction
		s.logger.Info("Evicting oldest IP for user",
			zap.String("user", email),
			zap.String("evicted_ip", removedIP),
			zap.Int64("evicted_ip_last_seen", removedIPData.LastSeen),
			zap.String("new_ip", ip))

		// Trim the list
		userData.IPs = userData.IPs[:s.maxIPsPerUser]

		// Update the reverse mapping
		if users, exists := s.ipToUsers[removedIP]; exists {
			delete(users, email)
			if len(users) == 0 {
				delete(s.ipToUsers, removedIP)
				s.logger.Debug("Removed IP from global tracking (no remaining users)", zap.String("ip", removedIP))
			}
		}
	}

	// Update the reverse mapping for the new IP
	if _, exists := s.ipToUsers[ip]; !exists {
		s.ipToUsers[ip] = make(map[string]struct{})
	}
	s.ipToUsers[ip][email] = struct{}{}

	// Mark as dirty and trigger immediate write
	s.dirty = true
	s.logger.Info("Added new IP for user", zap.String("user", email), zap.String("ip", ip))
	go s.writeImmediately()

	// Clean up expired users if TTL is set
	if s.userDataTTL > 0 {
		s.cleanupExpiredUsers()
	}

	return true
}

// HasIP checks if the given IP address belongs to any user.
func (s *UserIPStorage) HasIP(ip string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, exists := s.ipToUsers[ip]
	return exists
}

// GetUsersForIP returns all users associated with a given IP.
func (s *UserIPStorage) GetUsersForIP(ip string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	users := make([]string, 0)
	if userSet, exists := s.ipToUsers[ip]; exists {
		for user := range userSet {
			users = append(users, user)
		}
	}
	return users
}

// GetIPsForUser returns all IPs associated with a given user.
func (s *UserIPStorage) GetIPsForUser(email string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if userData, exists := s.userData[email]; exists {
		// Extract IP strings from IPData structs
		result := make([]string, len(userData.IPs))
		for i, ipData := range userData.IPs {
			result[i] = ipData.IP
		}
		return result
	}
	return []string{}
}

// writeImmediately writes data to disk immediately in a goroutine-safe manner
func (s *UserIPStorage) writeImmediately() {
	if err := s.PersistToDisk(false); err != nil {
		s.logger.Error("Failed to write data immediately", zap.Error(err))
	} else {
		s.logger.Debug("Successfully wrote data immediately")
	}
}

// persistData represents the structure of the data to be persisted.
type persistData struct {
	UserData map[string]*UserData `json:"user_data"`
	// We don't need to persist ipToUsers as it can be reconstructed
}

// LoadFromDisk loads the user IP data from disk.
func (s *UserIPStorage) LoadFromDisk() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Debug("Attempting to load data from disk", zap.String("path", s.persistPath))
	// Check if the file exists
	fileInfo, err := os.Stat(s.persistPath)
	if os.IsNotExist(err) {
		s.logger.Debug("Persistence file does not exist", zap.String("path", s.persistPath))
		// File doesn't exist, nothing to load
		return nil
	} else if err != nil {
		s.logger.Error("Error stating persistence file", zap.String("path", s.persistPath), zap.Error(err))
		return err
	}
	s.logger.Debug("Persistence file exists", zap.String("path", s.persistPath), zap.Int64("size", fileInfo.Size()))

	// Read the file
	data, err := os.ReadFile(s.persistPath)
	if err != nil {
		s.logger.Error("Error reading persistence file", zap.String("path", s.persistPath), zap.Error(err))
		return err
	}
	s.logger.Debug("Successfully read persistence file", zap.String("path", s.persistPath), zap.Int("bytes_read", len(data)))

	// Try to parse the JSON as new format first
	var pd persistData
	if err := json.Unmarshal(data, &pd); err != nil {
		s.logger.Error("Error unmarshalling persistence data", zap.String("path", s.persistPath), zap.Error(err))
		return err
	}

	// Check if migration is needed by detecting if this is legacy format
	// Try to parse a small sample to see if it's old format
	needsMigration := false
	if len(pd.UserData) > 0 {
		// Try parsing as legacy format to detect if migration is needed
		var testLegacy struct {
			UserData map[string]*legacyUserData `json:"user_data"`
		}
		if err := json.Unmarshal(data, &testLegacy); err == nil {
			// If legacy parsing succeeds, check if it actually has legacy structure
			for _, legacyData := range testLegacy.UserData {
				if len(legacyData.IPs) > 0 {
					// This is legacy format - IPs are strings not objects
					needsMigration = true
					break
				}
			}
		}
	}

	if needsMigration {
		s.logger.Info("Detected old data format, performing migration", zap.String("path", s.persistPath))
		if err := s.migrateFromLegacyFormat(data); err != nil {
			s.logger.Error("Migration failed", zap.Error(err))
			return err
		}
		s.logger.Info("Migration completed successfully")
	} else {
		// Update our data structures with new format
		s.userData = pd.UserData
		s.logger.Info("Loaded data from disk (new format)", zap.Int("user_count", len(pd.UserData)), zap.String("path", s.persistPath))
	}

	// Rebuild the reverse mapping
	s.ipToUsers = make(map[string]map[string]struct{})
	for user, userData := range s.userData {
		for _, ipData := range userData.IPs {
			if _, exists := s.ipToUsers[ipData.IP]; !exists {
				s.ipToUsers[ipData.IP] = make(map[string]struct{})
			}
			s.ipToUsers[ipData.IP][user] = struct{}{}
		}
	}

	s.dirty = false
	s.logger.Debug("Dirty flag set to false after loading from disk") // Debug log
	return nil
}

// migrateFromLegacyFormat converts old format data to new format
func (s *UserIPStorage) migrateFromLegacyFormat(data []byte) error {
	// Parse as legacy format
	var legacyPD struct {
		UserData map[string]*legacyUserData `json:"user_data"`
	}

	if err := json.Unmarshal(data, &legacyPD); err != nil {
		s.logger.Error("Failed to parse legacy format", zap.Error(err))
		return err
	}

	// Convert to new format
	s.userData = make(map[string]*UserData)
	for user, legacyData := range legacyPD.UserData {
		// Convert legacy IP strings to IPData structs
		newIPs := make([]IPData, len(legacyData.IPs))
		for i, ip := range legacyData.IPs {
			newIPs[i] = IPData{
				IP:       ip,
				LastSeen: legacyData.LastSeen, // Use the user's last seen for all IPs
			}
			if s.debugLogging {
				newIPs[i].LastSeenISO = time.Unix(legacyData.LastSeen, 0).Format("2006-01-02T15:04:05-07:00")
			}
		}

		s.userData[user] = &UserData{
			IPs: newIPs,
			// Don't set LastSeen in new format as it's per-IP now
		}

		s.logger.Info("Migrated user data",
			zap.String("user", user),
			zap.Int("ip_count", len(newIPs)),
			zap.Int64("legacy_last_seen", legacyData.LastSeen))
	}

	// Mark as dirty to ensure the new format gets written
	s.dirty = true
	s.logger.Info("Migration complete, will write new format to disk",
		zap.Int("migrated_users", len(s.userData)))

	return nil
}

// PersistToDisk saves the user IP data to disk. If force is false, it only persists if data has changed.
func (s *UserIPStorage) PersistToDisk(force bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Only persist if data has changed AND we are not forcing a write
	if !s.dirty && !force {
		return nil
	}

	// Prepare the data to persist
	pd := persistData{
		UserData: s.userData,
	}

	// Convert to JSON
	data, err := json.MarshalIndent(pd, "", "  ")
	if err != nil {
		return err
	}

	// Write to a temporary file first
	tempFile := s.persistPath + ".tmp"
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return err
	}

	// Rename the temporary file to the actual file (atomic operation)
	if err := os.Rename(tempFile, s.persistPath); err != nil {
		return err
	}

	s.dirty = false                                                    // Reset dirty flag after successful write
	s.logger.Debug("Dirty flag set to false after persisting to disk") // Debug log
	return nil
}

// IsDirty returns true if the data has changed since the last persist.
func (s *UserIPStorage) IsDirty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dirty
}

// cleanupExpiredUsers removes users whose data has expired based on TTL.
func (s *UserIPStorage) cleanupExpiredUsers() {
	s.logger.Debug("Starting cleanup of expired users")

	// Calculate the expiration timestamp
	expireTime := s.clock.Now().Unix() - int64(s.userDataTTL)
	s.logger.Debug("Calculated expiration time", zap.Int64("expire_time", expireTime))

	// Check each user
	for email, userData := range s.userData {
		// Find the most recent IP timestamp for this user
		mostRecentTime := int64(0)
		for _, ipData := range userData.IPs {
			if ipData.LastSeen > mostRecentTime {
				mostRecentTime = ipData.LastSeen
			}
		}

		s.logger.Debug("Checking user for expiration",
			zap.String("user", email),
			zap.Int64("most_recent_ip_time", mostRecentTime),
			zap.Int64("expire_time", expireTime))

		// If the user's most recent IP timestamp is older than the expiration time
		if mostRecentTime < expireTime {
			s.logger.Info("User data expired, removing user",
				zap.String("user", email),
				zap.Int64("most_recent_activity", mostRecentTime),
				zap.Int("ip_count", len(userData.IPs)))

			// Remove all IPs from the reverse mapping
			for _, ipData := range userData.IPs {
				s.logger.Debug("Removing IP from reverse mapping for expired user",
					zap.String("user", email),
					zap.String("ip", ipData.IP))
				if users, exists := s.ipToUsers[ipData.IP]; exists {
					delete(users, email)
					if len(users) == 0 {
						s.logger.Debug("Removing IP from global tracking (no remaining users)",
							zap.String("ip", ipData.IP))
						delete(s.ipToUsers, ipData.IP)
					}
				}
			}

			// Remove the user from the userData map
			delete(s.userData, email)

			// Mark as dirty and trigger immediate write
			s.dirty = true
			go s.writeImmediately()
		} else {
			s.logger.Debug("User data not expired", zap.String("user", email))
		}
	}
	s.logger.Debug("Finished cleanup of expired users")
}
