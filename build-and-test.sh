#!/bin/bash
set -e

# Build Caddy with our module
go mod tidy
xcaddy build --with github.com/shyndman/caddy-user-ip=.

# Test the configuration
./caddy validate --config test-config.json

echo "Configuration validated successfully!"
