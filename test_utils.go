package caddy_user_ip

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddytest"
	"github.com/jonboulle/clockwork"
)

// loggedClock wraps clockwork.FakeClock to provide logging and initial time setting.
type loggedClock struct {
	FakeClock *clockwork.FakeClock
	t         *testing.T
}

// Now returns the current time of the fake clock and logs the call.
func (mc *loggedClock) Now() time.Time {
	now := mc.FakeClock.Now()
	return now
}

// Advance advances the fake clock by the given duration and logs the call.
func (mc *loggedClock) Advance(d time.Duration) {
	mc.t.Logf("CLOCK: Advance(%v) called. Current time before: %v", d, mc.FakeClock.Now())
	mc.FakeClock.Advance(d)
	mc.t.Logf("CLOCK: Advance(%v) completed. Current time after: %v", d, mc.FakeClock.Now())
}

// Unix returns the Unix timestamp of the current time and logs the call.
// This wraps the standard time.Time.Unix() method for logging purposes.
func (mc *loggedClock) Unix() int64 {
	unixTime := mc.Now().Unix() // Use the wrapped Now() for consistency
	mc.t.Logf("CLOCK: Unix() called, returning %d", unixTime)
	return unixTime
}

// setupFakeClock initializes a fake clock, sets its initial time to 0,
// wraps it in a logging type, and injects it into the package-level variable.
// It also registers a cleanup function to reset the variable.
func setupFakeClock(t *testing.T) *loggedClock {
	t.Helper()
	// Initialize fake clock at Unix epoch 0
	fakeClock := clockwork.NewFakeClockAt(time.Unix(0, 0))
	mock := &loggedClock{
		FakeClock: fakeClock,
		t:         t,
	}
	testClockInject = mock.FakeClock // Assuming testClockInject is a package-level var in the main package
	t.Cleanup(func() { testClockInject = nil })
	t.Logf("CLOCK: Fake clock initialized at time 0 (%v)", mock.Now())
	return mock
}

// pollForUserData polls the persistence file until data for the specified user is found or a timeout occurs.
func pollForUserData(t *testing.T, path, email string, timeout, interval time.Duration) map[string]*UserData {
	t.Helper()
	timeoutChan := time.After(timeout)
	tick := time.NewTicker(interval)
	defer tick.Stop()

	for {
		select {
		case <-timeoutChan:
			t.Fatalf("Timeout waiting for data for user '%s' to be persisted", email)
		case <-tick.C:
			persistedUserData := readPersistedData(t, path)
			if _, exists := persistedUserData[email]; exists {
				return persistedUserData
			}
		}
	}
}

// createTester initializes a new caddytest.Tester with a standard header
// and the provided caddyfileFragment.
func createTester(t *testing.T, caddyfileFragment string) *caddytest.Tester {
	tester := caddytest.NewTester(t)
	fullCaddyfile := `
  {
    admin localhost:2999
    http_port     9080
    https_port    9443
    grace_period  1ns
		log {
		  format console
		}
		debug
  }

` + caddyfileFragment

	tester.InitServer(fullCaddyfile, "caddyfile")
	return tester
}

// createTempPersistFile creates a temporary file for persistence and returns its path.
// It also registers a cleanup function to remove the file after the test.
func createTempPersistFile(t *testing.T) string {
	tempDir, err := os.MkdirTemp("", "caddy-user-ip-test")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	t.Logf("INFO: Created temp persist directory: %s", tempDir)
	persistPath := filepath.Join(tempDir, "user_ips.json")
	t.Logf("INFO: Temp persist file path: %s", persistPath)

	t.Cleanup(func() {
		t.Logf("INFO: Cleaning up temp persist directory: %s", tempDir)
		// Ignoring error in test cleanup
		_ = os.RemoveAll(tempDir)
	})

	return persistPath
}

// readPersistedData reads and unmarshals the JSON content from the given path.
func readPersistedData(t *testing.T, path string) map[string]*UserData {
	t.Logf("INFO: Reading persisted data from: %s", path)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			t.Logf("INFO: Persist file does not exist: %s", path)
			return make(map[string]*UserData) // Return empty map as per original logic
		}
		t.Fatalf("ERROR: Failed to read persisted data file %s: %v", path, err)
	}

	t.Logf("INFO: Raw data read from %s: %s", path, string(data))

	// The persisted data is a JSON object with a "user_data" key
	var persistedFileContent struct {
		UserData map[string]*UserData `json:"user_data"`
	}
	if err := json.Unmarshal(data, &persistedFileContent); err != nil {
		t.Fatalf("ERROR: Failed to unmarshal persisted data from %s: %v", path, err)
	}

	return persistedFileContent.UserData
}

// Helper to send a request with specific headers
func sendTestRequest(t *testing.T, tester *caddytest.Tester, method, url, email, xff, xri string) *http.Response {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	if email != "" {
		req.Header.Set("X-Token-User-Email", email)
	}
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	if xri != "" {
		req.Header.Set("X-Real-IP", xri)
	}

	resp, err := tester.Client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	return resp
}

// getFileModTime returns the modification time of a file or an error.
func getFileModTime(t *testing.T, path string) (time.Time, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return time.Time{}, os.ErrNotExist
		}
		t.Fatalf("Failed to get file info for %s: %v", path, err)
		return time.Time{}, err // Should not be reached due to t.Fatalf
	}
	return fileInfo.ModTime(), nil
}
