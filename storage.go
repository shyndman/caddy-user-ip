// package caddy_user_ip provides Caddy middleware for tracking and matching user IPs.
package caddy_user_ip

import (
	"encoding/json"
	"os"
	"sync"

	"github.com/jonboulle/clockwork"
	"go.uber.org/zap" // Import the zap logging library
)

// UserData represents the data stored for each user
type UserData struct {
	// List of historical IPs (newest first)
	IPs []string `json:"ips"`

	// Timestamp of last activity (Unix timestamp in seconds)
	LastSeen int64 `json:"last_seen"`
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
}

// NewUserIPStorage creates a new UserIPStorage with the given configuration.
func NewUserIPStorage(persistPath string, maxIPsPerUser uint64, userDataTTL uint64,
	clock clockwork.Clock, logger *zap.Logger) *UserIPStorage {
	storage := &UserIPStorage{
		userData:      make(map[string]*UserData),
		ipToUsers:     make(map[string]map[string]struct{}),
		maxIPsPerUser: maxIPsPerUser,
		userDataTTL:   userDataTTL,
		persistPath:   persistPath,
		dirty:         false, // Initialize dirty flag
		clock:         clock,
		logger:        logger, // Assign the logger
	}
	storage.logger.Debug("UserIPStorage initialized with dirty=false") // Debug log
	return storage
}

// AddUserIP adds an IP address for a user, maintaining the FIFO limit.
// Returns true if the IP was newly added (not already in the user's list).
func (s *UserIPStorage) AddUserIP(email, ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get or create user data
	userData, exists := s.userData[email]
	if !exists {
		// Create new user data
		userData = &UserData{
			IPs:      []string{},
			LastSeen: s.clock.Now().Unix(),
		}
		s.userData[email] = userData
	} else {
		// Update last seen timestamp
		userData.LastSeen = s.clock.Now().Unix()

		// Check if this user already has this IP in their list
		foundIndex := -1
		for i, existingIP := range userData.IPs {
			if existingIP == ip {
				foundIndex = i
				break // Found the IP, no need to continue searching
			}
		}

		if foundIndex != -1 {
			// IP already exists for this user
			if foundIndex > 0 {
				// IP is not the most recent, move it to the front (MRU)
				// Remove the IP from its current position
				userData.IPs = append(userData.IPs[:foundIndex], userData.IPs[foundIndex+1:]...)

				// Prepend the IP to the front
				userData.IPs = append([]string{ip}, userData.IPs...)

				// Mark as dirty since data has changed
				s.dirty = true
				s.logger.Debug("Dirty flag set to true in AddUserIP (MRU reorder)", zap.String("user", email), zap.String("ip", ip)) // Debug log
			}
			// IP was already the most recent (foundIndex == 0) or has been moved to the front
			return false // No *new* IP was added
		}
	}

	// Add IP to user's list
	userData.IPs = append([]string{ip}, userData.IPs...)

	// Trim list if it exceeds the maximum
	if uint64(len(userData.IPs)) > s.maxIPsPerUser {
		// Get the IP that's being removed
		removedIP := userData.IPs[s.maxIPsPerUser]

		// Trim the list
		userData.IPs = userData.IPs[:s.maxIPsPerUser]

		// Update the reverse mapping
		if users, exists := s.ipToUsers[removedIP]; exists {
			delete(users, email)
			if len(users) == 0 {
				delete(s.ipToUsers, removedIP)
			}
		}
	}

	// Update the reverse mapping for the new IP
	if _, exists := s.ipToUsers[ip]; !exists {
		s.ipToUsers[ip] = make(map[string]struct{})
	}
	s.ipToUsers[ip][email] = struct{}{}

	// Mark as dirty since data has changed
	s.dirty = true
	s.logger.Debug("Dirty flag set to true in AddUserIP", zap.String("user", email)) // Debug log

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
		// Return a copy to prevent modification of the internal slice
		result := make([]string, len(userData.IPs))
		copy(result, userData.IPs)
		return result
	}
	return []string{}
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

	// Parse the JSON
	var pd persistData
	if err := json.Unmarshal(data, &pd); err != nil {
		s.logger.Error("Error unmarshalling persistence data", zap.String("path", s.persistPath), zap.Error(err))
		return err
	}
	s.logger.Debug("Successfully unmarshalled persistence data", zap.String("path", s.persistPath), zap.Int("unmarshalled_user_count", len(pd.UserData)))
	s.logger.Debug("Unmarshalled user data content", zap.Any("user_data", pd.UserData)) // Log the content for inspection

	// Update our data structures
	s.userData = pd.UserData
	s.logger.Info("Loaded data from disk", zap.Int("user_count", len(pd.UserData)), zap.String("path", s.persistPath)) // Info log

	// Rebuild the reverse mapping
	s.ipToUsers = make(map[string]map[string]struct{})
	for user, userData := range s.userData {
		for _, ip := range userData.IPs {
			if _, exists := s.ipToUsers[ip]; !exists {
				s.ipToUsers[ip] = make(map[string]struct{})
			}
			s.ipToUsers[ip][user] = struct{}{}
		}
	}

	s.dirty = false
	s.logger.Debug("Dirty flag set to false after loading from disk") // Debug log
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
	s.logger.Debug("Starting cleanup of expired users") // Debug log

	// Calculate the expiration timestamp
	expireTime := s.clock.Now().Unix() - int64(s.userDataTTL)
	s.logger.Debug("Calculated expiration time", zap.Int64("expire_time", expireTime)) // Debug log

	// Check each user
	for email, userData := range s.userData {
		s.logger.Debug("Checking user for expiration", zap.String("user", email), zap.Int64("last_seen", userData.LastSeen), zap.Int64("expire_time", expireTime)) // Debug log
		// If the user's last seen timestamp is older than the expiration time
		if userData.LastSeen < expireTime {
			s.logger.Debug("User data expired, removing user", zap.String("user", email)) // Debug log

			// Remove all IPs from the reverse mapping
			for _, ip := range userData.IPs {
				s.logger.Debug("Removing IP from reverse mapping for expired user", zap.String("user", email), zap.String("ip", ip)) // Debug log
				if users, exists := s.ipToUsers[ip]; exists {
					delete(users, email)
					if len(users) == 0 {
						s.logger.Debug("Removing IP from ipToUsers as no users remain", zap.String("ip", ip)) // Debug log
						delete(s.ipToUsers, ip)
					}
				}
			}

			// Remove the user from the userData map
			delete(s.userData, email)
			s.logger.Debug("Removed user from userData map", zap.String("user", email)) // Debug log

			// Mark as dirty since data has changed
			s.dirty = true
			s.logger.Debug("Dirty flag set to true in cleanupExpiredUsers", zap.String("user", email)) // Debug log
		} else {
			s.logger.Debug("User data not expired", zap.String("user", email)) // Debug log
		}
	}
	s.logger.Debug("Finished cleanup of expired users") // Debug log
}
