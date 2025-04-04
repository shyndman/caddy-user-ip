#!/bin/bash
set -e

# Clear any existing storage file
rm -f /tmp/user_ips.json

# Build Caddy with our module
cd ..
go mod tidy
xcaddy build --with github.com/shyndman/caddy-user-ip=.

# Run Caddy with our test configuration
./caddy run --config test/simple-matcher-test.Caddyfile &
CADDY_PID=$!

# Wait for Caddy to start
sleep 2

# First request should be from an unknown user
echo "Testing request from unknown user..."
RESPONSE=$(curl -s http://localhost:39504/)
echo "Response: $RESPONSE"
if [[ "$RESPONSE" != "Unknown user" ]]; then
  echo "Test failed: Expected 'Unknown user'"
  kill $CADDY_PID
  exit 1
fi

# Add a test user with the current IP
echo "Adding current IP to known IPs..."
curl -s -H "X-Token-User-Email: test@example.com" http://localhost:9876/ > /dev/null

# Now the request should be from a known user
echo "Testing request from known user..."
RESPONSE=$(curl -s http://localhost:9876/)
echo "Response: $RESPONSE"
if [[ "$RESPONSE" != "Known user" ]]; then
  echo "Test failed: Expected 'Known user'"
  kill $CADDY_PID
  exit 1
fi

# Clean up
kill $CADDY_PID
echo "All tests passed!"
