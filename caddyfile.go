package caddyhansestack

import (
	"strconv"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("hansestack", parseCaddyfile)
}

// parseCaddyfile is the httpcaddyfile.UnmarshalHandlerFunc registered for
// the top-level "hansestack" directive. It dispatches on the first argument
// (the Hansestack sub-module name), of which "leakcheck" is currently the
// only one.
//
//	hansestack leakcheck {
//	    api_key {$HANSESTACK_API_KEY}
//	    mode enrich_response
//	    password_field "password"
//	    header_leaked "X-Hansestack-Leaked"
//	    header_count "X-Hansestack-Leak-Count"
//	    block_status 401
//	}
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	d := h.Dispenser
	d.Next() // consume "hansestack"

	if !d.NextArg() {
		return nil, d.ArgErr()
	}

	switch d.Val() {
	case "leakcheck":
		m := new(Middleware)
		if err := m.UnmarshalCaddyfile(d); err != nil {
			return nil, err
		}
		return m, nil
	default:
		return nil, d.Errf("unrecognized hansestack sub-module %q", d.Val())
	}
}

// UnmarshalCaddyfile sets up the Middleware from Caddyfile tokens. The
// dispenser is expected to be positioned at the "leakcheck" argument token
// when this is called (i.e. immediately after parseCaddyfile has consumed
// the "hansestack" directive name).
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// Positioned at "leakcheck"; there must be no further arguments on this
	// line, only an opening block.
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "api_key":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.APIKey = d.Val()

		case "mode":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.Mode = d.Val()

		case "password_field":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.PasswordField = d.Val()

		case "header_leaked":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.HeaderLeaked = d.Val()

		case "header_count":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.HeaderCount = d.Val()

		case "block_status":
			if !d.NextArg() {
				return d.ArgErr()
			}
			status, err := strconv.Atoi(d.Val())
			if err != nil {
				return d.Errf("invalid block_status %q: %v", d.Val(), err)
			}
			m.BlockStatus = status

		default:
			return d.Errf("unrecognized hansestack leakcheck subdirective %q", d.Val())
		}

		if d.NextArg() {
			return d.ArgErr()
		}
	}

	return nil
}
