package caddy_user_ip

import (
	"strconv"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("user_ip_tracking", parseCaddyfile)
}

// parseCaddyfile unmarshals tokens from h into a new UserIpTracking middleware handler.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m UserIpTracking

	err := m.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}

	return &m, nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *UserIpTracking) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// Skip the directive name
	d.Next()

	// Process the block
	for d.NextBlock(0) {
		switch d.Val() {
		case "persist_path":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.PersistPath = d.Val()

		case "max_ips_per_user":
			if !d.NextArg() {
				return d.ArgErr()
			}
			var err error
			m.MaxIpsPerUser, err = strconv.ParseUint(d.Val(), 10, 32)
			if err != nil {
				return err
			}

		case "user_data_ttl":
			if !d.NextArg() {
				return d.ArgErr()
			}
			var err error
			m.UserDataTTL, err = strconv.ParseUint(d.Val(), 10, 32)
			if err != nil {
				return err
			}

		default:
			return d.Errf("unknown subdirective %q", d.Val())
		}
	}

	return nil
}
