#!/bin/bash
set -e

# Clear any existing storage file
rm -f /tmp/user_ips.json

# Build Caddy with our module
cd ..
go mod tidy
xcaddy build --with github.com/shyndman/caddy-user-ip=.

# Run Caddy with our test configuration
./caddy run --config test/simple-test.Caddyfile &
CADDY_PID=$!

# Wait for Caddy to start
sleep 2

# Make a request to add a user IP
echo "Adding user IP..."
curl -s -H "X-Token-User-Email: test@example.com" http://localhost:29628/

# Check if the IP was added to the storage file
echo "Checking storage file..."
cat /tmp/user_ips.json

# Clean up
kill $CADDY_PID
echo "Test complete!"
