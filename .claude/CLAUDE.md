# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Caddy v2 module that tracks authenticated users' IP addresses and provides request matching capabilities. The module consists of two main components:

1. **Middleware (`user_ip_tracking`)**: Tracks IP addresses for authenticated users identified by the `X-Token-User-Email` header
2. **Matcher (`user_ip`)**: Matches requests against known user IPs for conditional handling

## Architecture

- **tracker.go**: Main middleware implementation (`UserIpTracking` struct)
- **matcher.go**: Request matcher implementation (`UserIPMatcher` struct)  
- **storage.go**: In-memory and disk persistence for user IP data (`UserIPStorage` struct)
- **config.go**: Configuration structures and Caddyfile parsing
- **package.go**: Module registration and global storage reference

The middleware uses a global storage instance (`globalStorage`) to share data between the tracker and matcher components.

## Development Commands

### Build
```bash
go build -v ./...
```

### Test
```bash
go test -v ./...
```

### Run specific test
```bash
go test -v -run TestFunctionName ./...
```

### Lint (using golangci-lint)
```bash
golangci-lint run
```

### Build with xcaddy (for testing with Caddy)
```bash
xcaddy build --with github.com/shyndman/caddy-user-ip=.
```

## Testing

- Tests use the `clockwork` package for time mocking via `testClockInject`
- Test utilities are in `test_utils.go`
- Main test files: `tracker_test.go`, `matcher_test.go`

## Key Implementation Details

- IP detection priority: `X-Forwarded-For` → `X-Real-IP` → `RemoteAddr`
- User data persists to disk asynchronously when new IPs are added
- Background persistence occurs every 5 minutes for timestamp updates
- Graceful shutdown ensures final state persistence
- IPs are stored newest-first, limited by `max_ips_per_user` configuration