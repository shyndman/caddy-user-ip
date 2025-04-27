# Caddy User IP Tracking

A Caddy v2 module that tracks authenticated users' IP addresses and provides a matcher to identify requests from known user IPs.

## Overview

This middleware tracks IP addresses of authenticated users (identified by the `X-Token-User-Email` header) and provides a matcher that can be used in Caddy configurations to handle requests differently based on whether the client IP is associated with a known user.

Key features:
- Track IP addresses for authenticated users
- Persist user IP data to disk
- Configure maximum IPs stored per user
- Set time-to-live (TTL) for user data
- Match requests against known user IPs

## Installation

### Using xcaddy

```bash
xcaddy build --with github.com/shyndman/caddy-user-ip
```

### From source

```bash
git clone https://github.com/shyndman/caddy-user-ip.git
cd caddy-user-ip
go mod tidy
xcaddy build --with github.com/shyndman/caddy-user-ip=.
```

## Configuration

### Caddyfile Syntax

```
user_ip_tracking {
    persist_path <file_path>
    max_ips_per_user <number>
    user_data_ttl <seconds>
}
```

### Configuration Options

- `persist_path`: (Required) File path where user IP data will be stored
- `max_ips_per_user`: (Optional) Maximum number of recent IPs to store per user (default: 5)
- `user_data_ttl`: (Optional) Time-to-live for user data in seconds; after this period of inactivity, a user's data will be removed (default: 0, meaning no expiration)

### Matcher Syntax

```
@name user_ip
```

## Usage Examples

### Basic Example

```
{
    order user_ip_tracking before handle
}

example.com {
    user_ip_tracking {
        persist_path /var/lib/caddy/user_ips.json
        max_ips_per_user 5
        user_data_ttl 86400  # 24 hours
    }

    @known_users user_ip

    handle @known_users {
        respond "Welcome back!"
    }

    handle {
        respond "Hello, new visitor!"
    }
}
```

### Security Application

```
{
    order user_ip_tracking before handle
}

example.com {
    user_ip_tracking {
        persist_path /var/lib/caddy/user_ips.json
        max_ips_per_user 3
        user_data_ttl 604800  # 7 days
    }

    @admin_path path /admin/*
    @known_user_ip user_ip

    handle @admin_path {
        # Only allow access to admin area from known user IPs
        @unknown_ip not user_ip
        handle @unknown_ip {
            respond 403 {
                body "Access denied: Unknown IP address"
            }
        }

        # Continue with admin handlers for known IPs
        reverse_proxy admin_backend:8080
    }

    # Regular site content
    handle {
        reverse_proxy site_backend:8080
    }
}
```

## How It Works

1. The middleware captures the IP address of authenticated users (identified by the `X-Token-User-Email` header). The `last_seen` timestamp for the user is updated in memory on every request.
2. User data, including the list of known IPs and the `last_seen` timestamp, is stored in memory and persisted to disk to ensure durability across restarts. Persistence occurs under the following conditions:
    *   Immediately (asynchronously) when a **new IP address** is added for a user.
    *   Periodically (by default, every 5 minutes) in a background process, saving the current state including the latest `last_seen` timestamps.
    *   During a **graceful Caddy server shutdown**, ensuring the most recent state is saved.
3. The `user_ip` matcher checks if the client IP is in the list of known user IPs associated with any user.
4. Requests can be handled differently based on the matcher result.

### IP Detection

The middleware attempts to determine the client's IP address using the following methods (in order):
1. `X-Forwarded-For` header (first IP in the list)
2. `X-Real-IP` header
3. Request's `RemoteAddr`

## License

[MIT License](LICENSE)
