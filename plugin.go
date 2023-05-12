package lessor

import (
	"context"
	"errors"
	"fmt"
	caddy "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

type Middleware struct {
	Issuer   string
	provider *oidc.Provider
	logger   *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (m *Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.lessor",
		New: func() caddy.Module { return new(Middleware) },
	}
}

func init() {
	caddy.RegisterModule(&Middleware{})
	httpcaddyfile.RegisterHandlerDirective("lessor", parseCaddyfile)
}

// Provision implements caddy.Provisioner.
func (m *Middleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger() // g.logger is a *zap.Logger
	provider, err := oidc.NewProvider(ctx, m.Issuer)
	if err != nil {
		m.logger.Error("error provisioning issuer", zap.String("issuer", m.Issuer), zap.Error(err))
		return fmt.Errorf("erorr provisioning issuer '%s': %w", m.Issuer, err)
		// handle error
	}
	m.provider = provider
	return nil
}

// Validate implements caddy.Validator.
func (m *Middleware) Validate() error {
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	err := m.injectScopeHeader(r)
	if err != nil {
		return err
	}
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile sets up Lessor from Caddyfile tokens. Syntax:
// UnmarshalCaddyfile sets up the DNS provider from Caddyfile tokens. Syntax:
//
//	lessor [<issuer_url>] {
//	    issuer <issuer_url>
//	}
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			m.Issuer = d.Val()
		}
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "issuer":
				if m.Issuer != "" {
					return d.Err("Issuer already set")
				}
				m.Issuer = d.Val()
				if d.NextArg() {
					return d.ArgErr()
				}
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}
	return nil
}

func (m *Middleware) injectScopeHeader(r *http.Request) error {
	// Extract tenants and inject them into X-Scope-OrgID header
	tokenString := r.Header.Get("X-Id-Token")

	if len(tokenString) == 0 { // Skip
		return nil
	}

	verifier := m.provider.Verifier(&oidc.Config{})

	_, err := verifier.Verify(context.Background(), tokenString)
	if err != nil {
		m.logger.Error("failed to validate token", zap.Error(err), zap.String("token", tokenString), zap.Int("len", len(tokenString))) // TODO: remove after this works
		return fmt.Errorf("token verification failed: %w", err)
	}

	type DexClaims struct {
		LogReaders []string `json:"tenant:logreaders"`
		jwt.RegisteredClaims
	}

	token, err := jwt.ParseWithClaims(tokenString, &DexClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(""), nil
	})
	if !errors.Is(err, jwt.ErrTokenUnverifiable) {
		m.logger.Error("token parsing error", zap.Error(err))
		return fmt.Errorf("token parsing error: %w", err)
	}
	// Verified
	claims, ok := token.Claims.(*DexClaims)
	if !ok {
		m.logger.Error("invalid claims detected", zap.Error(err))
		return fmt.Errorf("invalid claims detected: %w", err)
	}
	if len(claims.LogReaders) > 0 {
		tenants := strings.Join(claims.LogReaders, "|")
		m.logger.Info("settings X-Scope-OrgID", zap.String("tenants", tenants))
		r.Header.Set("X-Scope-OrgID", tenants)
	} else {
		m.logger.Info("setting X-Scope-OrgID to fallback to fake tenant")
		r.Header.Set("X-Scope-OrgID", "fake") // Default to fake
	}
	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := &Middleware{}
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddy.Validator             = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)
