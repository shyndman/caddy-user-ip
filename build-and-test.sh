#!/bin/bash
set -e

# Build Caddy with our module
go mod tidy
xcaddy build --with github.com/shyndman/caddy-user-ip=.

# Test the smoke test Caddyfile configuration
./caddy validate --config test/smoke-test.Caddyfile

echo "Configuration validated successfully!"

# Run Caddy with our configuration to see the logs
echo "\nRunning Caddy with our smoke test configuration..."
./caddy run --config test/smoke-test.Caddyfile
