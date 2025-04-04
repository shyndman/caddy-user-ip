#!/bin/bash
set -e

# Clear any existing storage file

# Build Caddy with our module
cd ..
go mod tidy
xcaddy build --with github.com/shyndman/caddy-user-ip=.

# Run Caddy with our test configuration
rm -f /tmp/matcher-test.user_ips.json
./caddy run --config test/matcher-test.Caddyfile &
CADDY_PID=$!

# Wait for Caddy to start
sleep 4

# First request should be from an unknown IP
echo "Testing request from unknown IP..."
RESPONSE=$(curl -s http://localhost:9876/)
echo "Response: $RESPONSE"
if [[ "$RESPONSE" != "Request from unknown IP!" ]]; then
  echo "Test failed: Expected 'Request from unknown IP!'"
  kill $CADDY_PID
  exit 1
fi

# Add a test user with the current IP
echo "Adding current IP to known IPs..."
curl -s -H "X-Token-User-Email: test@example.com" http://localhost:9876/ > /dev/null

# Now the request should be from a known IP
echo "Testing request from known IP..."
RESPONSE=$(curl -s -H "X-Test-Header: true" http://localhost:9876/)
echo "Response: $RESPONSE"
if [[ "$RESPONSE" != "Request from known user IP!" ]]; then
  echo "Test failed: Expected 'Request from known user IP!'"
  kill $CADDY_PID
  exit 1
fi

# Clean up
kill $CADDY_PID
echo "All tests passed!"
