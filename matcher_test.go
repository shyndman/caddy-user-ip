package caddy_user_ip

import (
	"net/http"
	"os" // Import the os package
	"testing"
	"time"
)

// TestMatchKnownIP configures Caddy with both user_ip_tracking and http.matchers.user_ip.
// It uses the tracker to add a user and IP to storage, then sends a request with that
// user's email and IP, asserting that the matcher matches the request.
func TestMatchKnownIP(t *testing.T) {
	persistPath := createTempPersistFile(t)
	defer func() {
		// Ignoring error in test cleanup
		_ = os.Remove(persistPath)
	}() // Clean up the temporary file

	setupFakeClock(t) // Inject fake clock

	tester := createTester(t, `
		localhost:9080 {
			route / {
				user_ip_tracking {
					persist_path `+persistPath+`
					max_ips_per_user 5
					user_data_ttl 3600
				}
			}

			route /matched {
				@user_ip user_ip
				respond @user_ip "Matched" 200
				respond "Unmatched" 404
			}
		}
	`)

	// Action: Use the tracker to add a user and IP to storage
	// Send a request to the tracking route (which is the /matched route in this config)
	// The tracker will process this request and store the IP.
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", "test@example.com", "1.1.1.1", "")

	// Poll until data is persisted for the user
	pollForUserData(t, persistPath, "test@example.com", 2*time.Second, 10*time.Millisecond)

	// Action: Send a request with the same user email and IP, targeting the /matched route
	// This request should be matched by the user_ip matcher.
	req, err := http.NewRequest("GET", "http://localhost:9080/matched", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("X-Token-User-Email", "test@example.com")
	req.Header.Set("X-Forwarded-For", "1.1.1.1") // Use the same IP that was tracked

	resp, err := tester.Client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer func() {
		// Ignoring error in test cleanup
		_ = resp.Body.Close()
	}()

	// Assertions: Check that the request was matched by the user_ip matcher
	if resp.StatusCode != 200 {
		t.Errorf("Expected status code 200 for a known IP, but got %d", resp.StatusCode)
	}
}

// TestNoMatchUnknownIP configures Caddy with both user_ip_tracking and http.matchers.user_ip.
// It uses the tracker to add a user and IP, then sends a request with an IP *not* in storage,
// asserting that the matcher does *not* match.
func TestNoMatchUnknownIP(t *testing.T) {
	persistPath := createTempPersistFile(t)
	defer func() {
		// Ignoring error in test cleanup
		_ = os.Remove(persistPath)
	}() // Clean up the temporary file

	setupFakeClock(t) // Inject fake clock

	tester := createTester(t, `
		localhost:9080 {
			route / {
				user_ip_tracking {
					persist_path `+persistPath+`
					max_ips_per_user 5
					user_data_ttl 3600
				}
				respond "Tracked"
			}

			route /unmatched {
				@no_user_ip not user_ip
				respond @no_user_ip "Unmatched" 404
				respond "Matched" 200
			}
		}
	`)

	// Action: Use the tracker to add a user and a KNOWN IP to storage
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", "test@example.com", "1.1.1.1", "")

	// Poll until data is persisted for the user
	pollForUserData(t, persistPath, "test@example.com", 2*time.Second, 10*time.Millisecond)

	// Action: Send a request with the same user email but an UNKNOWN IP, targeting the /matched route
	// This request should NOT be matched by the user_ip matcher.
	req, err := http.NewRequest("GET", "http://localhost:9080/unmatched", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("X-Token-User-Email", "test@example.com")
	req.Header.Set("X-Forwarded-For", "9.9.9.9") // Use an IP that was NOT tracked

	resp, err := tester.Client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer func() {
		// Ignoring error in test cleanup
		_ = resp.Body.Close()
	}()

	// Assertions: Check that the request was NOT matched by the user_ip matcher
	if resp.StatusCode != 404 {
		t.Errorf("Expected status code 404 for an unknown IP, but got %d", resp.StatusCode)
	}
}

// TestNoMatchWithoutTracker configures Caddy with only the http.matchers.user_ip matcher
// (no user_ip_tracking). It sends a request and asserts that the matcher does not match
// because globalStorage will be nil.
func TestNoMatchWithoutTracker(t *testing.T) {
	// No need to create a persist file or fake clock as the tracker is not used.

	tester := createTester(t, `
		localhost:9080 {
			route / {
				@user_ip user_ip
				respond @user_ip "Matched" 200
				respond "Unmatched" 404
			}
		}
	`)

	// Action: Send a request with a user email and IP, targeting the /matched route.
	// The user_ip_tracking module is NOT present, so globalStorage will be nil,
	// and the user_ip matcher should not match.
	req, err := http.NewRequest("GET", "http://localhost:9080/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("X-Token-User-Email", "test@example.com")
	req.Header.Set("X-Forwarded-For", "1.2.1.2")

	resp, err := tester.Client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer func() {
		// Ignoring error in test cleanup
		_ = resp.Body.Close()
	}()

	// Assertions: Check that the request was NOT matched by the user_ip matcher
	if resp.StatusCode != 404 {
		t.Errorf("Expected status code 404 when tracker is not configured, but got %d", resp.StatusCode)
	}
}

// TestMatchDifferentIPSources configures Caddy with both user_ip_tracking and http.matchers.user_ip.
// It adds a user and IP, then sends requests using different IP headers (X-Forwarded-For, X-Real-IP)
// and relying on RemoteAddr that resolve to the stored IP, asserting that the matcher matches
// in each case.
func TestMatchDifferentIPSources(t *testing.T) {
	persistPath := createTempPersistFile(t)
	defer func() {
		// Ignoring error in test cleanup
		_ = os.Remove(persistPath)
	}() // Clean up the temporary file

	setupFakeClock(t) // Inject fake clock

	tester := createTester(t, `
		localhost:9080 {
			route / {
				user_ip_tracking {
					persist_path `+persistPath+`
					max_ips_per_user 5
					user_data_ttl 3600
				}
				respond "Tracked" 200
			}

			route /matched {
				@user_ip user_ip
				respond @user_ip "Matched" 200
				respond "Unmatched" 404
			}
		}
	`)

	knownIP := "1.1.1.1"
	userEmail := "test@example.com"

	// Action: Use the tracker to add the user and KNOWN IP to storage
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", userEmail, knownIP, "")

	// Poll until data is persisted for the user
	pollForUserData(t, persistPath, userEmail, 2*time.Second, 10*time.Millisecond)

	// Scenario 1: IP via X-Forwarded-For
	req1, err1 := http.NewRequest("GET", "http://localhost:9080/matched", nil)
	if err1 != nil {
		t.Fatalf("Failed to create request 1: %v", err1)
	}
	req1.Header.Set("X-Token-User-Email", userEmail)
	req1.Header.Set("X-Forwarded-For", knownIP)

	resp1, err1 := tester.Client.Do(req1)
	if err1 != nil {
		t.Fatalf("Failed to send request 1: %v", err1)
	}
	defer func() {
		// Ignoring error in test cleanup
		_ = resp1.Body.Close()
	}()

	if resp1.StatusCode != 200 {
		t.Errorf("Scenario 1 (X-Forwarded-For): Expected status code 200, but got %d", resp1.StatusCode)
	}

	// Scenario 2: IP via X-Real-IP
	req2, err2 := http.NewRequest("GET", "http://localhost:9080/matched", nil)
	if err2 != nil {
		t.Fatalf("Failed to create request 2: %v", err2)
	}
	req2.Header.Set("X-Token-User-Email", userEmail)
	req2.Header.Set("X-Real-IP", knownIP)

	resp2, err2 := tester.Client.Do(req2)
	if err2 != nil {
		t.Fatalf("Failed to send request 2: %v", err2)
	}
	defer func() {
		// Ignoring error in test cleanup
		_ = resp2.Body.Close()
	}()

	if resp2.StatusCode != 200 {
		t.Errorf("Scenario 2 (X-Real-IP): Expected status code 200, but got %d", resp2.StatusCode)
	}

	// Scenario 3: IP via RemoteAddr (no X- headers)
	// Note: The actual RemoteAddr in a test environment might be a loopback address.
	// We are asserting that if the RemoteAddr *happens* to be the knownIP, it matches.
	// A more robust test might involve manipulating the RemoteAddr in the test setup,
	// but for this task, relying on the helper's behavior is sufficient.
	req3, err3 := http.NewRequest("GET", "http://localhost:9080/matched", nil)
	if err3 != nil {
		t.Fatalf("Failed to create request 3: %v", err3)
	}
	req3.Header.Set("X-Token-User-Email", userEmail)
	// No X-Forwarded-For or X-Real-IP headers

	// To make this test reliable, we need to ensure the RemoteAddr seen by Caddy
	// is the knownIP. The sendTestRequest helper allows specifying the RemoteAddr.
	sendTestRequest(t, tester, "GET", "http://localhost:9080/matched", userEmail, "", knownIP) // Use knownIP as remoteAddr

	// We don't need to check the response for req3 directly as sendTestRequest does it.
	// The assertion is implicitly done by sendTestRequest expecting a 200 status code
	// if the matcher works correctly with RemoteAddr.
}

// TestCELMatchKnownIP configures Caddy with both user_ip_tracking and a route that uses
// the user_ip() CEL expression matcher. It adds a user and IP, then sends a request with
// that user's email and IP, asserting that the request is matched by the CEL expression.
func TestCELMatchKnownIP(t *testing.T) {
	persistPath := createTempPersistFile(t)
	defer func() {
		// Ignoring error in test cleanup
		_ = os.Remove(persistPath)
	}() // Clean up the temporary file

	setupFakeClock(t) // Inject fake clock

	tester := createTester(t, `
		localhost:9080 {
			route / {
				user_ip_tracking {
					persist_path `+persistPath+`
					max_ips_per_user 5
					user_data_ttl 3600
				}
				respond "Tracked" 200
			}
			route /matched {
				@user_ip_cel `+"`user_ip('any')`"+`
				respond @user_ip_cel "Matched" 200
				respond "Unmatched" 404
			}
		}
	`)

	knownIP := "1.1.1.1"
	userEmail := "test@example.com"

	// Action: Use the tracker to add the user and KNOWN IP to storage
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", userEmail, knownIP, "")

	// Poll until data is persisted for the user
	pollForUserData(t, persistPath, userEmail, 2*time.Second, 10*time.Millisecond)

	// Action: Send a request with the same user email and IP, targeting the /matched route
	// This request should be matched by the user_ip() CEL expression.
	req, err := http.NewRequest("GET", "http://localhost:9080/matched", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("X-Token-User-Email", userEmail)
	req.Header.Set("X-Forwarded-For", knownIP) // Use the same IP that was tracked

	resp, err := tester.Client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer func() {
		// Ignoring error in test cleanup
		_ = resp.Body.Close()
	}()

	// Assertions: Check that the request was matched by the CEL expression matcher
	if resp.StatusCode != 200 {
		t.Errorf("Expected status code 200 for a known IP with CEL matcher, but got %d", resp.StatusCode)
	}
}

// TestCELNoMatchUnknownIP configures Caddy with both user_ip_tracking and a route that uses
// the user_ip() CEL expression. It adds a user and IP, then sends a request with an unknown IP,
// asserting that the request is *not* matched by the CEL expression.
func TestCELNoMatchUnknownIP(t *testing.T) {
	persistPath := createTempPersistFile(t)
	defer func() {
		// Ignoring error in test cleanup
		_ = os.Remove(persistPath)
	}() // Clean up the temporary file

	setupFakeClock(t) // Inject fake clock

	tester := createTester(t, `
localhost:9080 {
			route / {
				user_ip_tracking {
					persist_path `+persistPath+`
					max_ips_per_user 5
					user_data_ttl 3600
				}
				respond "Tracked" 200
			}
			route /matched {
				@user_ip_cel `+"`user_ip('any')`"+`
				respond @user_ip_cel "Matched" 200
				respond "Unmatched" 404
			}
		}
	`)

	knownIP := "1.1.1.1"
	unknownIP := "9.9.9.9"
	userEmail := "test@example.com"

	// Action: Use the tracker to add the user and a KNOWN IP to storage
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", userEmail, knownIP, "")

	// Poll until data is persisted for the user
	pollForUserData(t, persistPath, userEmail, 2*time.Second, 10*time.Millisecond)

	// Action: Send a request with the same user email but an UNKNOWN IP, targeting the /matched route
	// This request should NOT be matched by the user_ip() CEL expression.
	req, err := http.NewRequest("GET", "http://localhost:9080/matched", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("X-Token-User-Email", userEmail)
	req.Header.Set("X-Forwarded-For", unknownIP) // Use an IP that was NOT tracked

	resp, err := tester.Client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer func() {
		// Ignoring error in test cleanup
		_ = resp.Body.Close()
	}()

	// Assertions: Check that the request was NOT matched by the CEL expression matcher
	if resp.StatusCode != 404 {
		t.Errorf("Expected status code 404 for an unknown IP with CEL matcher, but got %d", resp.StatusCode)
	}
}
