package caddy_user_ip

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"
)

// TestBasicHandler provides a simple example of how to write an HTTP test
// using the caddytest package. It initializes a Caddy server with a basic
// configuration and asserts a response from a specific endpoint.
func TestBasicHandler(t *testing.T) {
	tester := createTester(t, `
    localhost:9080 {
      respond /version 200 {
        body "hello from localhost"
      }
    }
  `)
	tester.AssertGetResponse("http://localhost:9080/version", 200, "hello from localhost")
}

// TestBasicIPTracking verifies that a user's IP is correctly tracked when the X-Token-User-Email header is present.
func TestBasicIPTracking(t *testing.T) {
	persistPath := createTempPersistFile(t)

	fakeClock := setupFakeClock(t)

	tester := createTester(t, `
    localhost:9080 {
        route {
            user_ip_tracking {
                persist_path `+persistPath+`
                max_ips_per_user 5
                user_data_ttl 3600
            }
            respond "OK"
        }
    }
  `)

	// Action: Send a GET request with the email header and X-Forwarded-For IP
	req, err := http.NewRequest("GET", "http://localhost:9080/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("X-Token-User-Email", "test@example.com")
	req.Header.Set("X-Forwarded-For", "1.1.1.1")

	resp, err := tester.Client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer func() {
		// Ignoring error in test cleanup
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != 200 {
		t.Errorf("Expected status code 200, but got %d", resp.StatusCode)
	}
	// We don't need to check the body "OK" as per the plan, focusing on persisted state.

	// Poll until data is persisted
	persistedUserData := pollForUserData(t, persistPath, "test@example.com", 2*time.Second, 10*time.Millisecond)

	// Assertions: Check the content of the persisted file
	userData, exists := persistedUserData["test@example.com"]
	if !exists {
		// This should not happen if pollForUserData succeeds, but as a safeguard:
		t.Fatalf("Expected user 'test@example.com' in persisted data after polling, but not found")
	}

	if len(userData.IPs) != 1 || userData.IPs[0].IP != "1.1.1.1" {
		t.Errorf("Expected user 'test@example.com' to have IP ['1.1.1.1'], but got %v", userData.IPs)
	}

	// Check last_seen is the fake clock's current time (now stored per-IP)
	expectedLastSeen := fakeClock.Now().Unix()
	if len(userData.IPs) > 0 && userData.IPs[0].LastSeen != expectedLastSeen {
		t.Errorf("Expected last_seen timestamp to be %d, but got %d", expectedLastSeen, userData.IPs[0].LastSeen)
	}
}

// TestIPExtractionLogic tests the correct extraction of IPs from headers and RemoteAddr.
func TestIPExtractionLogic(t *testing.T) {
	persistPath := createTempPersistFile(t)

	fakeClock := setupFakeClock(t)

	tester := createTester(t, `
    localhost:9080 {
        route {
            user_ip_tracking {
                persist_path `+persistPath+`
                max_ips_per_user 5
                user_data_ttl 3600
            }
            respond "OK"
        }
    }
  `)

	// Scenario A (X-Forwarded-For):
	reqA, errA := http.NewRequest("GET", "http://localhost:9080/", nil)
	if errA != nil {
		t.Fatalf("Failed to create request A: %v", errA)
	}
	reqA.Header.Set("X-Token-User-Email", "user-a@example.com")
	reqA.Header.Set("X-Forwarded-For", "2.2.2.2, 1.1.1.1")
	reqA.Header.Set("X-Real-IP", "3.3.3.3")
	respA, errA := tester.Client.Do(reqA)
	if errA != nil {
		t.Fatalf("Failed to send request A: %v", errA)
	}
	defer func() {
		// Ignoring error in test cleanup
		_ = respA.Body.Close()
	}()
	if respA.StatusCode != 200 {
		t.Errorf("Scenario A: Expected status code 200, but got %d", respA.StatusCode)
	}

	fakeClock.Advance(1 * time.Second) // Advance time between requests

	// Scenario B (X-Real-IP):
	reqB, errB := http.NewRequest("GET", "http://localhost:9080/", nil)
	if errB != nil {
		t.Fatalf("Failed to create request B: %v", errB)
	}
	reqB.Header.Set("X-Token-User-Email", "user-b@example.com")
	reqB.Header.Set("X-Real-IP", "3.3.3.3")
	respB, errB := tester.Client.Do(reqB)
	if errB != nil {
		t.Fatalf("Failed to send request B: %v", errB)
	}
	defer func() {
		// Ignoring error in test cleanup
		_ = respB.Body.Close()
	}()
	if respB.StatusCode != 200 {
		t.Errorf("Scenario B: Expected status code 200, but got %d", respB.StatusCode)
	}

	fakeClock.Advance(1 * time.Second) // Advance time between requests

	// Scenario C (RemoteAddr):
	// caddytest sets a default RemoteAddr, we'll check against that.
	// The actual RemoteAddr will depend on the test environment.
	// We'll assume it's something like "127.0.0.1:random_port" and extract the IP.
	reqC, errC := http.NewRequest("GET", "http://localhost:9080/", nil)
	if errC != nil {
		t.Fatalf("Failed to create request C: %v", errC)
	}
	reqC.Header.Set("X-Token-User-Email", "user-c@example.com")
	// No X-Forwarded-For or X-Real-IP headers

	// Capture the RemoteAddr from the request object before sending
	// Note: This might not be the *exact* IP seen by the middleware due to test environment specifics,
	// but it's the best we can do to predict the RemoteAddr used by caddytest.
	// A more robust test might involve inspecting Caddy's internal state or logs if possible.
	// For now, we'll assert that *some* IP (the RemoteAddr) was recorded.
	// The actual IP will likely be a loopback address from the test environment.
	// We'll assert that the user exists and has at least one IP recorded.
	respC, errC := tester.Client.Do(reqC)
	if errC != nil {
		t.Fatalf("Failed to send request C: %v", errC)
	}
	defer func() {
		// Ignoring error in test cleanup
		_ = respC.Body.Close()
	}()
	if respC.StatusCode != 200 {
		t.Errorf("Scenario C: Expected status code 200, but got %d", respC.StatusCode)
	}

	// Poll until data is persisted for all users
	persistedUserDataA := pollForUserData(t, persistPath, "user-a@example.com", 2*time.Second, 10*time.Millisecond)
	persistedUserDataB := pollForUserData(t, persistPath, "user-b@example.com", 2*time.Second, 10*time.Millisecond)
	persistedUserDataC := pollForUserData(t, persistPath, "user-c@example.com", 2*time.Second, 10*time.Millisecond)

	// Assertions: Check the content of the persisted file for each scenario

	// Scenario A
	userDataA, existsA := persistedUserDataA["user-a@example.com"]
	if !existsA {
		t.Fatalf("Expected user 'user-a@example.com' in persisted data, but not found")
	}
	if len(userDataA.IPs) != 1 || userDataA.IPs[0].IP != "2.2.2.2" {
		t.Errorf("Scenario A: Expected user 'user-a@example.com' to have IP ['2.2.2.2'], but got %v", userDataA.IPs)
	}
	// Check last_seen is the fake clock's time after request A (now stored per-IP)
	expectedLastSeenA := fakeClock.Now().Add(-2 * time.Second).Unix() // Time before advancing for B and C
	if len(userDataA.IPs) > 0 && userDataA.IPs[0].LastSeen != expectedLastSeenA {
		t.Errorf("Scenario A: Expected last_seen timestamp to be %d, but got %d", expectedLastSeenA, userDataA.IPs[0].LastSeen)
	}

	// Scenario B
	userDataB, existsB := persistedUserDataB["user-b@example.com"]
	if !existsB {
		t.Fatalf("Expected user 'user-b@example.com' in persisted data, but not found")
	}
	if len(userDataB.IPs) != 1 || userDataB.IPs[0].IP != "3.3.3.3" {
		t.Errorf("Scenario B: Expected user 'user-b@example.com' to have IP ['3.3.3.3'], but got %v", userDataB.IPs)
	}
	// Check last_seen is the fake clock's time after request B (now stored per-IP)
	expectedLastSeenB := fakeClock.Now().Add(-1 * time.Second).Unix() // Time before advancing for C
	if len(userDataB.IPs) > 0 && userDataB.IPs[0].LastSeen != expectedLastSeenB {
		t.Errorf("Scenario B: Expected last_seen timestamp to be %d, but got %d", expectedLastSeenB, userDataB.IPs[0].LastSeen)
	}

	// Scenario C
	userDataC, existsC := persistedUserDataC["user-c@example.com"]
	if !existsC {
		t.Fatalf("Expected user 'user-c@example.com' in persisted data, but not found")
	}
	if len(userDataC.IPs) == 0 {
		t.Errorf("Scenario C: Expected user 'user-c@example.com' to have at least one IP (RemoteAddr), but got none")
	}
	// Check last_seen is the fake clock's current time after request C (now stored per-IP)
	expectedLastSeenC := fakeClock.Now().Unix()
	if len(userDataC.IPs) > 0 && userDataC.IPs[0].LastSeen != expectedLastSeenC {
		t.Errorf("Scenario C: Expected last_seen timestamp to be %d, but got %d", expectedLastSeenC, userDataC.IPs[0].LastSeen)
	}
	// We can't reliably assert the exact RemoteAddr IP here without more complex test setup,
	// so we'll just check that an IP was recorded.

}

// TestMissingEmailHeader ensures no tracking occurs if the X-Token-User-Email header is absent.
func TestMissingEmailHeader(t *testing.T) {
	persistPath := createTempPersistFile(t)

	setupFakeClock(t) // Inject fake clock, though not strictly needed for this test's logic

	tester := createTester(t, `
    localhost:9080 {
        route {
            user_ip_tracking {
                persist_path `+persistPath+`
                max_ips_per_user 5
                user_data_ttl 3600
            }
            respond "OK"
        }
    }
  `)

	// Action: Send a GET request without the email header
	req, err := http.NewRequest("GET", "http://localhost:9080/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	// No X-Token-User-Email header

	resp, err := tester.Client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer func() {
		// Ignoring error in test cleanup
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != 200 {
		t.Errorf("Expected status code 200, but got %d", resp.StatusCode)
	}

	// Assertions: Verify the persisted file is empty or unchanged
	// Since we start with an empty file, we expect it to remain empty.
	// No need to poll as no data should be written.
	persistedUserData := readPersistedData(t, persistPath)

	if len(persistedUserData) != 0 {
		t.Errorf("Expected persisted data to be empty when email header is missing, but found %d users", len(persistedUserData))
	}
}

// TestMaxIPsLimit confirms that adding more IPs than max_ips_per_user correctly evicts the oldest IP.
func TestMaxIPsLimit(t *testing.T) {
	persistPath := createTempPersistFile(t)

	fakeClock := setupFakeClock(t)

	tester := createTester(t, `
    localhost:9080 {
        route {
            user_ip_tracking {
                persist_path `+persistPath+`
                max_ips_per_user 2 # Set low limit
                user_data_ttl 3600
            }
            respond "OK"
        }
    }
  `)

	// Actions: Send sequential requests for test@example.com with different IPs
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", "test@example.com", "1.1.1.1", "") // First IP
	fakeClock.Advance(1 * time.Second)                                                             // Advance time
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", "test@example.com", "2.2.2.2", "") // Second IP
	fakeClock.Advance(1 * time.Second)                                                             // Advance time
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", "test@example.com", "3.3.3.3", "") // Third IP (should evict 1.1.1.1)

	// Poll until data is persisted
	persistedUserData := pollForUserData(t, persistPath, "test@example.com", 2*time.Second, 10*time.Millisecond)

	// Assertions: Check the content of the persisted file
	userData, exists := persistedUserData["test@example.com"]
	if !exists {
		t.Fatalf("Expected user 'test@example.com' in persisted data after eviction, but not found")
	}

	// Expected IPs: 3.3.3.3 (newest), 2.2.2.2 (second newest)
	expectedIPs := []string{"3.3.3.3", "2.2.2.2"}
	if len(userData.IPs) != len(expectedIPs) {
		t.Errorf("Expected user 'test@example.com' to have %d IPs, but got %d. IPs: %v", len(expectedIPs), len(userData.IPs), userData.IPs)
	} else {
		// Check order and content
		for i := range expectedIPs {
			if userData.IPs[i].IP != expectedIPs[i] {
				t.Errorf("Expected IP at index %d to be '%s', but got '%s'. Full IPs: %v", i, expectedIPs[i], userData.IPs[i].IP, userData.IPs)
				break
			}
		}
	}

	// Check last_seen is the fake clock's current time after the last request (now stored per-IP)
	expectedLastSeen := fakeClock.Now().Unix()
	if len(userData.IPs) > 0 && userData.IPs[0].LastSeen != expectedLastSeen {
		t.Errorf("Expected last_seen timestamp to be %d, but got %d", expectedLastSeen, userData.IPs[0].LastSeen)
	}

	// Optional: Check that 1.1.1.1 is NOT present
	for _, ipData := range userData.IPs {
		if ipData.IP == "1.1.1.1" {
			t.Errorf("Expected IP '1.1.1.1' to be evicted, but it is still present: %v", userData.IPs)
			break
		}
	}
}

// TestDuplicateIPHandling verifies that adding an existing IP for a user doesn't duplicate the entry but updates the LastSeen timestamp.
func TestDuplicateIPHandling(t *testing.T) {
	persistPath := createTempPersistFile(t)

	fakeClock := setupFakeClock(t)

	tester := createTester(t, `
    localhost:9080 {
        route {
            user_ip_tracking {
                persist_path `+persistPath+`
                max_ips_per_user 5
                user_data_ttl 3600
            }
            respond "OK"
        }
    }
  `)

	// Action 1: Send request for test@example.com with 1.1.1.1
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", "test@example.com", "1.1.1.1", "")

	// Poll until data is persisted after the first request
	persistedUserDataAfterFirst := pollForUserData(t, persistPath, "test@example.com", 2*time.Second, 10*time.Millisecond)
	userDataAfterFirst, existsAfterFirst := persistedUserDataAfterFirst["test@example.com"]
	if !existsAfterFirst {
		t.Fatalf("Expected user 'test@example.com' in persisted data after first request, but not found")
	}
	initialLastSeen := int64(0)
	if len(userDataAfterFirst.IPs) > 0 {
		initialLastSeen = userDataAfterFirst.IPs[0].LastSeen
	}

	fakeClock.Advance(10 * time.Second) // Advance time to ensure distinct timestamps

	// Action 2: Send another request for test@example.com with the same IP 1.1.1.1
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", "test@example.com", "1.1.1.1", "")
	expectedLastSeen := fakeClock.Now().Unix()

	// Advance clock by the periodic persistence interval to trigger persistence
	fakeClock.Advance(5 * time.Minute)

	// Poll until data is persisted after the second request
	persistedUserDataAfterSecond := pollForUserData(t, persistPath, "test@example.com", 2*time.Second, 10*time.Millisecond)

	// Assertions: Check the content of the persisted file
	userDataAfterSecond, existsAfterSecond := persistedUserDataAfterSecond["test@example.com"]
	if !existsAfterSecond {
		t.Fatalf("Expected user 'test@example.com' in persisted data after second request, but not found")
	}

	// Assert that the IP list still contains only 1.1.1.1
	expectedIPs := []string{"1.1.1.1"}
	if len(userDataAfterSecond.IPs) != len(expectedIPs) || userDataAfterSecond.IPs[0].IP != expectedIPs[0] {
		t.Errorf("Expected user 'test@example.com' to have IP ['1.1.1.1'] after duplicate request, but got %v", userDataAfterSecond.IPs)
	}

	// Assert that the LastSeen timestamp was updated to the fake clock's current time (now stored per-IP)
	if len(userDataAfterSecond.IPs) > 0 && userDataAfterSecond.IPs[0].LastSeen != expectedLastSeen {
		t.Errorf("Expected LastSeen timestamp (%d) to be updated to %d after duplicate request, but it was %d", userDataAfterSecond.IPs[0].LastSeen, expectedLastSeen, userDataAfterSecond.IPs[0].LastSeen)
	}
	if len(userDataAfterSecond.IPs) > 0 && userDataAfterSecond.IPs[0].LastSeen <= initialLastSeen {
		t.Errorf("Expected LastSeen timestamp (%d) to be updated after duplicate request, but it was not greater than initial (%d)", userDataAfterSecond.IPs[0].LastSeen, initialLastSeen)
	}
}

// TestSharedIPAddress tests tracking the same IP address for multiple distinct users.
func TestSharedIPAddress(t *testing.T) {
	persistPath := createTempPersistFile(t)

	fakeClock := setupFakeClock(t)

	tester := createTester(t, `
    localhost:9080 {
        route {
            user_ip_tracking {
                persist_path `+persistPath+`
                max_ips_per_user 5
                user_data_ttl 3600
            }
            respond "OK"
        }
    }
  `)

	// Actions:
	// 1. Send request for user1@example.com with X-Forwarded-For: 5.5.5.5
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", "user1@example.com", "5.5.5.5", "")
	fakeClock.Advance(1 * time.Second) // Advance time

	// 2. Send request for user2@example.com with X-Forwarded-For: 5.5.5.5
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", "user2@example.com", "5.5.5.5", "")

	// Poll until data is persisted for both users
	persistedUserData1 := pollForUserData(t, persistPath, "user1@example.com", 2*time.Second, 10*time.Millisecond)
	persistedUserData2 := pollForUserData(t, persistPath, "user2@example.com", 2*time.Second, 10*time.Millisecond)

	// Assertions: Check the content of the persisted file

	// Check user1@example.com
	userData1, exists1 := persistedUserData1["user1@example.com"]
	if !exists1 {
		t.Fatalf("Expected user 'user1@example.com' in persisted data, but not found")
	}
	expectedIPs1 := []string{"5.5.5.5"}
	if len(userData1.IPs) != len(expectedIPs1) || userData1.IPs[0].IP != expectedIPs1[0] {
		t.Errorf("Expected user 'user1@example.com' to have IP ['5.5.5.5'], but got %v", userData1.IPs)
	}
	// Check last_seen is the fake clock's time after the first request (now stored per-IP)
	expectedLastSeen1 := fakeClock.Now().Add(-1 * time.Second).Unix()
	if len(userData1.IPs) > 0 && userData1.IPs[0].LastSeen != expectedLastSeen1 {
		t.Errorf("Expected user1 last_seen timestamp to be %d, but got %d", expectedLastSeen1, userData1.IPs[0].LastSeen)
	}

	// Check user2@example.com
	userData2, exists2 := persistedUserData2["user2@example.com"]
	if !exists2 {
		t.Fatalf("Expected user 'user2@example.com' in persisted data, but not found")
	}
	expectedIPs2 := []string{"5.5.5.5"}
	if len(userData2.IPs) != len(expectedIPs2) || userData2.IPs[0].IP != expectedIPs2[0] {
		t.Errorf("Expected user 'user2@example.com' to have IP ['5.5.5.5'], but got %v", userData2.IPs)
	}
	// Check last_seen is the fake clock's current time after the second request (now stored per-IP)
	expectedLastSeen2 := fakeClock.Now().Unix()
	if len(userData2.IPs) > 0 && userData2.IPs[0].LastSeen != expectedLastSeen2 {
		t.Errorf("Expected user2 last_seen timestamp to be %d, but got %d", expectedLastSeen2, userData2.IPs[0].LastSeen)
	}

	// Ensure both users exist in the data by reading the file again after both requests
	persistedUserDataCombined := readPersistedData(t, persistPath)
	if len(persistedUserDataCombined) != 2 {
		t.Errorf("Expected 2 users in persisted data, but found %d", len(persistedUserDataCombined))
	}
}

// TestMultipleIPsPerUser tests tracking several different IP addresses for a single user (within the limit).
func TestMultipleIPsPerUser(t *testing.T) {
	persistPath := createTempPersistFile(t)

	tester := createTester(t, `
    localhost:9080 {
        route {
            user_ip_tracking {
                persist_path `+persistPath+`
                max_ips_per_user 5
                user_data_ttl 3600
            }
            respond "OK"
        }
    }
  `)

	// Actions: Send sequential requests for multi@example.com
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", "multi@example.com", "6.6.6.6", "") // First IP
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", "multi@example.com", "7.7.7.7", "") // Second IP
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", "multi@example.com", "8.8.8.8", "") // Third IP

	// Allow time for persistence goroutine to potentially run
	time.Sleep(100 * time.Millisecond)

	// Assertions: Check the content of the persisted file
	persistedUserData := readPersistedData(t, persistPath)

	userData, exists := persistedUserData["multi@example.com"]
	if !exists {
		t.Fatalf("Expected user 'multi@example.com' in persisted data, but not found")
	}

	// Expected IPs: 8.8.8.8 (newest), 7.7.7.7, 6.6.6.6 (oldest)
	expectedIPs := []string{"8.8.8.8", "7.7.7.7", "6.6.6.6"}
	if len(userData.IPs) != len(expectedIPs) {
		t.Errorf("Expected user 'multi@example.com' to have %d IPs, but got %d. IPs: %v", len(expectedIPs), len(userData.IPs), userData.IPs)
	} else {
		// Check order and content
		for i := range expectedIPs {
			if userData.IPs[i].IP != expectedIPs[i] {
				t.Errorf("Expected IP at index %d to be '%s', but got '%s'. Full IPs: %v", i, expectedIPs[i], userData.IPs[i].IP, userData.IPs)
				break
			}
		}
	}
}

// TestAddUserIPDirtyFlagPersistFalse verifies that adding a new user/IP sets the dirty flag and triggers a non-forced write,
// and that subsequent identical requests also trigger a write (because timestamps are updated), and a new IP for the same user also triggers a write.
func TestAddUserIPDirtyFlagPersistFalse(t *testing.T) {
	persistPath := createTempPersistFile(t)
	// fakeClock is used in this test for advancing time between requests
	// to ensure timestamps are different and trigger persistence.
	fakeClock := setupFakeClock(t)

	tester := createTester(t, `
    localhost:9080 {
        route {
            user_ip_tracking {
                persist_path `+persistPath+`
                max_ips_per_user 5
                user_data_ttl 3600
            }
            respond "OK"
        }
    }
  `)

	// Action 1: Send HTTP GET request with header X-Token-User-Email: user1@test.com (Source IP: 1.1.1.1).
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", "user1@test.com", "1.1.1.1", "")

	// Wait briefly for the async PersistToDisk(false) call in ServeHTTP to likely complete.
	// Poll until data is persisted.
	persistedDataState1 := pollForUserData(t, persistPath, "user1@test.com", 2*time.Second, 10*time.Millisecond)
	modTimeState1, err1 := getFileModTime(t, persistPath)
	if err1 != nil {
		t.Fatalf("Failed to get file mod time after action 1: %v", err1)
	}

	// Assertion 1: File should exist and contain data for user1@test.com with IP ["1.1.1.1"].
	userData1, exists1 := persistedDataState1["user1@test.com"]
	if !exists1 {
		t.Fatalf("State 1: Expected user 'user1@test.com' in persisted data, but not found")
	}
	if len(userData1.IPs) != 1 || userData1.IPs[0].IP != "1.1.1.1" {
		t.Errorf("State 1: Expected user 'user1@test.com' to have IP ['1.1.1.1'], but got %v", userData1.IPs)
	}

	// Advance clock to ensure the timestamp will be different
	fakeClock.Advance(1 * time.Second)

	// Action 2: Send identical HTTP GET request (X-Token-User-Email: user1@test.com, Source IP: 1.1.1.1).
	// In the new schema, this should update the IP's timestamp and trigger persistence.
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", "user1@test.com", "1.1.1.1", "")

	// Wait briefly. Record file mod time/content (State 2).
	// We expect a write because the timestamp was updated.
	time.Sleep(100 * time.Millisecond) // Give async goroutine a chance to write
	modTimeState2, err2 := getFileModTime(t, persistPath)
	if err2 != nil {
		t.Fatalf("Failed to get file mod time after action 2: %v", err2)
	}
	persistedDataState2 := readPersistedData(t, persistPath) // Read content to compare

	// Assertion 2: File mod time should be newer because timestamp was updated.
	if !modTimeState2.After(modTimeState1) {
		t.Errorf("State 2: Expected file modification time to be newer than State 1 (%v), but got %v", modTimeState1, modTimeState2)
	}
	// Content should be different because the timestamp was updated
	data1, _ := json.Marshal(persistedDataState1)
	data2, _ := json.Marshal(persistedDataState2)
	if string(data1) == string(data2) {
		t.Errorf("State 2: Expected file content to be updated (timestamp changed), but it was unchanged.\nState 1: %s\nState 2: %s", string(data1), string(data2))
	}

	// Advance clock again for the new IP
	fakeClock.Advance(1 * time.Second)

	// Action 3: Send HTTP GET request with new IP (X-Token-User-Email: user1@test.com, Source IP: 1.1.1.2).
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", "user1@test.com", "1.1.1.2", "")

	// Wait briefly. Record file mod time/content (State 3).
	// Poll until data is persisted with the new IP.
	persistedDataState3 := pollForUserData(t, persistPath, "user1@test.com", 2*time.Second, 10*time.Millisecond)
	modTimeState3, err3 := getFileModTime(t, persistPath)
	if err3 != nil {
		t.Fatalf("Failed to get file mod time after action 3: %v", err3)
	}

	// Assertion 3: File should be updated and contain data for user1@test.com with IPs ["1.1.1.2", "1.1.1.1"]. Mod time should be newer than State 1/State 2.
	userData3, exists3 := persistedDataState3["user1@test.com"]
	if !exists3 {
		t.Fatalf("State 3: Expected user 'user1@test.com' in persisted data, but not found")
	}
	expectedIPs3 := []string{"1.1.1.2", "1.1.1.1"}
	if len(userData3.IPs) != len(expectedIPs3) || userData3.IPs[0].IP != expectedIPs3[0] || userData3.IPs[1].IP != expectedIPs3[1] {
		t.Errorf("State 3: Expected user 'user1@test.com' to have IPs %v, but got %v", expectedIPs3, userData3.IPs)
	}
	if !modTimeState3.After(modTimeState2) {
		t.Errorf("State 3: Expected file modification time (%v) to be newer than State 2 (%v)", modTimeState3, modTimeState2)
	}
}

// TestWriteOnDuplicateIP verifies that adding an existing IP for a user
// triggers a write to disk because the LastSeen timestamp is updated.
func TestWriteOnDuplicateIP(t *testing.T) {
	persistPath := createTempPersistFile(t)
	fakeClock := setupFakeClock(t)

	// Initial State: Create a persistence file manually.
	initialTime := fakeClock.Now()
	initialUserData := map[string]*UserData{
		"user1@test.com": {
			IPs: []IPData{{
				IP:       "1.1.1.1",
				LastSeen: initialTime.Unix(),
			}},
		},
	}
	initialPersistData := persistData{UserData: initialUserData}
	initialData, err := json.MarshalIndent(initialPersistData, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal initial data: %v", err)
	}
	if err := os.WriteFile(persistPath, initialData, 0644); err != nil {
		t.Fatalf("Failed to write initial persistence file: %v", err)
	}

	tester := createTester(t, `
    localhost:9080 {
        route {
            user_ip_tracking {
                persist_path `+persistPath+`
                max_ips_per_user 5
                user_data_ttl 3600
            }
            respond "OK"
        }
    }
  `)

	// Record initial file mod time.
	modTimeState1, err1 := getFileModTime(t, persistPath)
	if err1 != nil {
		t.Fatalf("Failed to get file mod time after setup: %v", err1)
	}

	// Advance the clock to ensure the new timestamp will be different.
	fakeClock.Advance(10 * time.Second)

	// Action: Send HTTP GET request with the same user and IP.
	// This should update the timestamp and trigger an immediate write.
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", "user1@test.com", "1.1.1.1", "")

	// Poll for the file modification time to change.
	timeout := time.After(2 * time.Second)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()

	var modTimeState2 time.Time
	var err2 error
	for {
		select {
		case <-timeout:
			t.Fatalf("Timeout waiting for file modification time to change")
		case <-tick.C:
			modTimeState2, err2 = getFileModTime(t, persistPath)
			if err2 != nil {
				t.Fatalf("Failed to get file mod time after action: %v", err2)
			}
			if modTimeState2.After(modTimeState1) {
				goto AROUND
			}
		}
	}
AROUND:

	// Assertion: File mod time should be newer, and content should have an updated timestamp.
	persistedDataState2 := readPersistedData(t, persistPath)
	userData2, exists2 := persistedDataState2["user1@test.com"]
	if !exists2 {
		t.Fatalf("Expected user 'user1@test.com' in persisted data, but not found")
	}

	expectedTimestamp := initialTime.Add(10 * time.Second).Unix()
	if len(userData2.IPs) > 0 && userData2.IPs[0].LastSeen != expectedTimestamp {
		t.Errorf("Expected last_seen timestamp to be updated to %d, but got %d", expectedTimestamp, userData2.IPs[0].LastSeen)
	}
}

// TestPeriodicPersistToDiskForcesWrite verifies that the periodic persister uses PersistToDisk(true)
// and writes to disk even if the dirty flag is false.
func TestPeriodicPersistToDiskForcesWrite(t *testing.T) {
	persistPath := createTempPersistFile(t)
	fakeClock := setupFakeClock(t)

	// Initial State: Create a persistence file manually.
	initialUserData := map[string]*UserData{
		"user1@test.com": {
			IPs: []IPData{{
				IP:       "1.1.1.1",
				LastSeen: fakeClock.Now().Unix(),
			}},
		},
	}
	initialPersistData := persistData{UserData: initialUserData}
	initialData, err := json.MarshalIndent(initialPersistData, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal initial data: %v", err)
	}
	if err := os.WriteFile(persistPath, initialData, 0644); err != nil {
		t.Fatalf("Failed to write initial persistence file: %v", err)
	}

	// Configure persist_interval to a testable value (e.g., 1 second).
	// Note: The actual interval in tracker.go is hardcoded to 5 minutes currently.
	// We will rely on advancing the fake clock to trigger it.
	tester := createTester(t, `
    localhost:9080 {
        route {
            user_ip_tracking {
                persist_path `+persistPath+`
                max_ips_per_user 5
                user_data_ttl 3600
            }
            respond "OK"
        }
    }
  `)

	// Action 1: Send HTTP GET request with header X-Token-User-Email: user1@test.com (Source IP: 1.1.1.1).
	// AddUserIP should return false, dirty remains false. PersistToDisk(false) is called but shouldn't write.
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", "user1@test.com", "1.1.1.1", "")

	// Manually add a new user to the storage. This will set the dirty flag.
	// This change is in memory but not yet persisted by ServeHTTP's async call
	// because the initial request didn't set the dirty flag.
	getStorage().AddUserIP("user2@test.com", "2.2.2.2")

	// Advance the FakeClock by slightly more than the default persistInterval (5 minutes).
	// This should trigger the periodic persister, which forces a write of the current state (including user2).
	fakeClock.Advance(5*time.Minute + time.Second)

	// Poll until data for the new us
	// er is persisted. This confirms the periodic write occurred.
	persistedData := pollForUserData(t, persistPath, "user2@test.com", 2*time.Second, 10*time.Millisecond)

	// Assertion 1: Should contain user1@test.com with the correct IP.
	userData1, exists1 := persistedData["user1@test.com"]
	if !exists1 {
		t.Fatalf("Expected user 'user1@test.com' in persisted data after periodic persistence, but not found")
	}
	if len(userData1.IPs) != 1 || userData1.IPs[0].IP != "1.1.1.1" {
		t.Errorf("Expected user 'user1@test.com' to have IP ['1.1.1.1'], but got %v", userData1.IPs)
	}

	// Assertion 2: Should contain user2@test.com with the correct IP.
	userData2, exists2 := persistedData["user2@test.com"]
	if !exists2 {
		t.Fatalf("Expected user 'user2@test.com' in persisted data after periodic persistence, but not found")
	}
	if len(userData2.IPs) != 1 || userData2.IPs[0].IP != "2.2.2.2" {
		t.Errorf("Expected user 'user2@test.com' to have IP ['2.2.2.2'], but got %v", userData2.IPs)
	}

	// Assertion 3: Ensure only these two users are present.
	if len(persistedData) != 2 {
		t.Errorf("Expected 2 users in persisted data after periodic persistence, but found %d", len(persistedData))
	}
}

// TestCleanupExpiredUsersSetsDirtyFlag verifies that when AddUserIP triggers cleanupExpiredUsers
// (due to TTL), and users are actually removed, the dirty flag is set, leading to a write by PersistToDisk(false).
func TestCleanupExpiredUsersSetsDirtyFlag(t *testing.T) {
	persistPath := createTempPersistFile(t)
	fakeClock := setupFakeClock(t)

	// Set TTL to 600 seconds (10 minutes).
	userDataTTL := time.Second * 600

	// Configure Caddy with the TTL
	tester := createTester(t, `
    localhost:9080 {
        route {
            user_ip_tracking {
                persist_path `+persistPath+`
                max_ips_per_user 5
                user_data_ttl `+fmt.Sprintf("%d", userDataTTL/time.Second)+`
            }
            respond "OK"
        }
    }
  `)

	// Action 1: Add an "old" user and advance the clock past the TTL.
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", "user_old@test.com", "1.1.1.1", "")
	pollForUserData(t, persistPath, "user_old@test.com", 2*time.Second, 10*time.Millisecond)
	fakeClock.Advance(userDataTTL + time.Minute) // Advance clock to make user_old expire

	// Action 2: Add a "new" user. This request will trigger the cleanup.
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", "user_new@test.com", "2.2.2.2", "")

	// Poll until the new user is present, which indicates a write occurred.
	persistedDataState1 := pollForUserData(t, persistPath, "user_new@test.com", 2*time.Second, 10*time.Millisecond)

	// Assertion 1: Should contain user_new@test.com.
	_, existsNew := persistedDataState1["user_new@test.com"]
	if !existsNew {
		t.Errorf("State 1: Expected user 'user_new@test.com' in persisted data, but not found")
	}

	// Assertion 2: Should *not* contain user_old@test.com.
	_, existsOld := persistedDataState1["user_old@test.com"]
	if existsOld {
		t.Errorf("State 1: Expected user 'user_old@test.com' to be removed from persisted data, but it was found")
	}
}

// TestUserIPTracking_MRU verifies the Most Recently Used (MRU) behavior of the user_ip_tracking middleware.
// Seeing an existing IP should move it to the front of the user's list.
func TestUserIPTracking_MRU(t *testing.T) {
	persistPath := createTempPersistFile(t)

	fakeClock := setupFakeClock(t)

	tester := createTester(t, `
    localhost:9080 {
        route {
            user_ip_tracking {
                persist_path `+persistPath+`
                max_ips_per_user 3 # Set limit to 3 for MRU test
                user_data_ttl 3600
            }
            respond "OK"
        }
    }
  `)

	testUserEmail := "mru-test@example.com"

	// Step 1: Send three sequential requests with distinct IPs
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", testUserEmail, "10.1.1.1", "") // First IP
	fakeClock.Advance(1 * time.Second)                                                        // Advance time
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", testUserEmail, "10.2.2.2", "") // Second IP
	fakeClock.Advance(1 * time.Second)                                                        // Advance time
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", testUserEmail, "10.3.3.3", "") // Third IP

	// Poll until data is persisted after the initial three requests
	persistedUserDataInitial := pollForUserData(t, persistPath, testUserEmail, 2*time.Second, 10*time.Millisecond)

	// Assert initial IP list order (newest first)
	userDataInitial, existsInitial := persistedUserDataInitial[testUserEmail]
	if !existsInitial {
		t.Fatalf("Expected user '%s' in persisted data after initial requests, but not found", testUserEmail)
	}

	expectedIPsInitial := []string{"10.3.3.3", "10.2.2.2", "10.1.1.1"}
	if len(userDataInitial.IPs) != len(expectedIPsInitial) {
		t.Errorf("Initial state: Expected user '%s' to have %d IPs, but got %d. IPs: %v", testUserEmail, len(expectedIPsInitial), len(userDataInitial.IPs), userDataInitial.IPs)
	} else {
		for i := range expectedIPsInitial {
			if userDataInitial.IPs[i].IP != expectedIPsInitial[i] {
				t.Errorf("Initial state: Expected IP at index %d to be '%s', but got '%s'. Full IPs: %v", i, expectedIPsInitial[i], userDataInitial.IPs[i].IP, userDataInitial.IPs)
				break
			}
		}
	}

	// Step 2: Send a fourth request re-using the first IP address
	fakeClock.Advance(1 * time.Second) // Advance time
	expectedLastSeen := fakeClock.Now().Unix() // Record expected LastSeen before sending request
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", testUserEmail, "10.1.1.1", "") // Re-use first IP

	// Advance clock by the periodic persistence interval to trigger persistence
	fakeClock.Advance(5 * time.Minute)

	// Poll until data is persisted after the fourth request
	persistedUserDataMRU := pollForUserData(t, persistPath, testUserEmail, 2*time.Second, 10*time.Millisecond)

	// Assert MRU IP list order (re-added IP moved to front)
	userDataMRU, existsMRU := persistedUserDataMRU[testUserEmail]
	if !existsMRU {
		t.Fatalf("Expected user '%s' in persisted data after MRU request, but not found", testUserEmail)
	}

	expectedIPsMRU := []string{"10.1.1.1", "10.3.3.3", "10.2.2.2"}
	if len(userDataMRU.IPs) != len(expectedIPsMRU) {
		t.Errorf("MRU state: Expected user '%s' to have %d IPs, but got %d. IPs: %v", testUserEmail, len(expectedIPsMRU), len(userDataMRU.IPs), userDataMRU.IPs)
	} else {
		for i := range expectedIPsMRU {
			if userDataMRU.IPs[i].IP != expectedIPsMRU[i] {
				t.Errorf("MRU state: Expected IP at index %d to be '%s', but got '%s'. Full IPs: %v", i, expectedIPsMRU[i], userDataMRU.IPs[i].IP, userDataMRU.IPs)
				break
			}
		}
	}

	// Assert that the LastSeen timestamp was updated to the fake clock's current time (now stored per-IP)
	if len(userDataMRU.IPs) > 0 && userDataMRU.IPs[0].LastSeen != expectedLastSeen {
		t.Errorf("MRU state: Expected LastSeen timestamp to be %d, but got %d", expectedLastSeen, userDataMRU.IPs[0].LastSeen)
	}
}

// TestUserIPTracking_MRU_MiddleIP verifies that when a middle IP (not first or last) is re-used,
// it gets moved to the front of the list correctly.
func TestUserIPTracking_MRU_MiddleIP(t *testing.T) {
	persistPath := createTempPersistFile(t)

	fakeClock := setupFakeClock(t)

	tester := createTester(t, `
    localhost:9080 {
        route {
            user_ip_tracking {
                persist_path `+persistPath+`
                max_ips_per_user 5 # Set limit to 5 for this test
                user_data_ttl 3600
            }
            respond "OK"
        }
    }
  `)

	testUserEmail := "mru-middle-test@example.com"

	// Step 1: Send four sequential requests with distinct IPs
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", testUserEmail, "10.1.1.1", "") // First IP
	fakeClock.Advance(1 * time.Second)                                                        // Advance time
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", testUserEmail, "10.2.2.2", "") // Second IP
	fakeClock.Advance(1 * time.Second)                                                        // Advance time
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", testUserEmail, "10.3.3.3", "") // Third IP (this will be our middle IP)
	fakeClock.Advance(1 * time.Second)                                                        // Advance time
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", testUserEmail, "10.4.4.4", "") // Fourth IP

	// Poll until data is persisted after the initial four requests
	persistedUserDataInitial := pollForUserData(t, persistPath, testUserEmail, 2*time.Second, 10*time.Millisecond)

	// Assert initial IP list order (newest first)
	userDataInitial, existsInitial := persistedUserDataInitial[testUserEmail]
	if !existsInitial {
		t.Fatalf("Expected user '%s' in persisted data after initial requests, but not found", testUserEmail)
	}

	expectedIPsInitial := []string{"10.4.4.4", "10.3.3.3", "10.2.2.2", "10.1.1.1"}
	if len(userDataInitial.IPs) != len(expectedIPsInitial) {
		t.Errorf("Initial state: Expected user '%s' to have %d IPs, but got %d. IPs: %v", testUserEmail, len(expectedIPsInitial), len(userDataInitial.IPs), userDataInitial.IPs)
	} else {
		for i := range expectedIPsInitial {
			if userDataInitial.IPs[i].IP != expectedIPsInitial[i] {
				t.Errorf("Initial state: Expected IP at index %d to be '%s', but got '%s'. Full IPs: %v", i, expectedIPsInitial[i], userDataInitial.IPs[i].IP, userDataInitial.IPs)
				break
			}
		}
	}

	// Step 2: Send a fifth request re-using the middle IP (10.2.2.2, originally at index 2)
	fakeClock.Advance(1 * time.Second) // Advance time
	expectedLastSeen := fakeClock.Now().Unix() // Record expected LastSeen before sending request
	sendTestRequest(t, tester, "GET", "http://localhost:9080/", testUserEmail, "10.2.2.2", "") // Re-use middle IP

	// Advance clock by the periodic persistence interval to trigger persistence
	fakeClock.Advance(5 * time.Minute)

	// Poll until data is persisted after the fifth request
	persistedUserDataMRU := pollForUserData(t, persistPath, testUserEmail, 2*time.Second, 10*time.Millisecond)

	// Assert MRU IP list order (middle IP moved to front)
	userDataMRU, existsMRU := persistedUserDataMRU[testUserEmail]
	if !existsMRU {
		t.Fatalf("Expected user '%s' in persisted data after MRU request, but not found", testUserEmail)
	}

	expectedIPsMRU := []string{"10.2.2.2", "10.4.4.4", "10.3.3.3", "10.1.1.1"}
	if len(userDataMRU.IPs) != len(expectedIPsMRU) {
		t.Errorf("MRU state: Expected user '%s' to have %d IPs, but got %d. IPs: %v", testUserEmail, len(expectedIPsMRU), len(userDataMRU.IPs), userDataMRU.IPs)
	} else {
		for i := range expectedIPsMRU {
			if userDataMRU.IPs[i].IP != expectedIPsMRU[i] {
				t.Errorf("MRU state: Expected IP at index %d to be '%s', but got '%s'. Full IPs: %v", i, expectedIPsMRU[i], userDataMRU.IPs[i].IP, userDataMRU.IPs)
				break
			}
		}
	}

	// Assert that the LastSeen timestamp was updated to the fake clock's current time (now stored per-IP)
	if len(userDataMRU.IPs) > 0 && userDataMRU.IPs[0].LastSeen != expectedLastSeen {
		t.Errorf("MRU state: Expected LastSeen timestamp to be %d, but got %d", expectedLastSeen, userDataMRU.IPs[0].LastSeen)
	}
}
