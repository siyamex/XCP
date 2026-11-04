package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/siyamex/XCP/internal/apperr"
	"github.com/siyamex/XCP/internal/ids"
	"github.com/siyamex/XCP/internal/store"
	"github.com/siyamex/XCP/internal/validate"
)

// API tokens (ADR-0021) look like xcp_<8 hex>_<48 hex>. The first part
// finds the row; only the SHA-256 of the whole token is stored.
const (
	tokenPrefix    = "xcp_"
	MaxTokens      = 20
	maxTokenDays   = 365
	tokenIDHexLen  = 8
	tokenSecretHex = 48
)

// ErrTokenIP is returned for a token used from an address it does not allow.
var ErrTokenIP = errors.New("this API token may not be used from this address")

// Token is the API view of a token.
type Token struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"` // xcp_<8 hex>: enough to recognise it
	Scope      string     `json:"scope"`
	IPAllow    []string   `json:"ip_allow"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	LastUsedIP string     `json:"last_used_ip"`
}

// NewToken is a token made just now: the only time its secret is shown.
type NewToken struct {
	Token
	Secret string `json:"secret"`
}

// TokenInput makes a token.
type TokenInput struct {
	Name        string   `json:"name"`
	Scope       string   `json:"scope"`
	ExpiresDays int      `json:"expires_days"` // 0: never
	IPAllow     []string `json:"ip_allow"`
	Password    string   `json:"password"` // the login's own, to confirm
}

func tokenView(t store.APIToken) Token {
	var allow []string
	_ = json.Unmarshal([]byte(t.IPAllow), &allow)
	if allow == nil {
		allow = []string{}
	}
	return Token{
		ID: t.ID, Name: t.Name, Prefix: tokenPrefix + t.Prefix, Scope: t.Scope, IPAllow: allow,
		CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, LastUsedAt: t.LastUsedAt, LastUsedIP: t.LastUsedIP,
	}
}

func randomHex(n int) (string, error) {
	b := make([]byte, n/2)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func tokenHash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

func fieldErr(field, code, msg string) error {
	return validate.WithField(&validate.Error{Code: code, Message: msg}, field)
}

// ListTokens returns the login's tokens.
func (s *Service) ListTokens(ctx context.Context, p *Principal) ([]Token, error) {
	ts, err := s.db.TokensOf(ctx, p.Login.ID)
	if err != nil {
		return nil, err
	}
	out := make([]Token, 0, len(ts))
	for _, t := range ts {
		out = append(out, tokenView(t))
	}
	return out, nil
}

// CreateToken makes a token for the login, after confirming its password.
func (s *Service) CreateToken(ctx context.Context, c Client, p *Principal, in TokenInput) (NewToken, error) {
	name := strings.TrimSpace(in.Name)
	switch {
	case name == "" || len(name) > 60 || strings.ContainsAny(name, "\r\n\x00"):
		return NewToken{}, fieldErr("name", validate.CodeFormat, "1 to 60 characters on one line")
	case in.Scope != store.TokenRead && in.Scope != store.TokenWrite:
		return NewToken{}, fieldErr("scope", validate.CodeFormat, "read or write")
	case in.ExpiresDays < 0 || in.ExpiresDays > maxTokenDays:
		return NewToken{}, fieldErr("expires_days", validate.CodeOutOfRange, "0 (never) to 365")
	case len(in.IPAllow) > 20:
		return NewToken{}, fieldErr("ip_allow", validate.CodeOutOfRange, "at most 20 networks")
	}
	allow := make([]string, 0, len(in.IPAllow))
	for _, n := range in.IPAllow {
		pre, err := parseNetwork(n)
		if err != nil {
			return NewToken{}, fieldErr("ip_allow", validate.CodeFormat, n+" is not an IP address or network")
		}
		allow = append(allow, pre.String())
	}
	if err := s.checkPassword(ctx, c, p.Login, in.Password, "auth.token"); err != nil {
		return NewToken{}, err
	}
	n, err := store.CountTokens(ctx, s.db.R, p.Login.ID)
	if err != nil {
		return NewToken{}, err
	}
	if n >= MaxTokens {
		return NewToken{}, apperr.NewConflict("limit_reached", "at most 20 API tokens per login")
	}
	idHex, err := randomHex(tokenIDHexLen)
	if err != nil {
		return NewToken{}, err
	}
	secret, err := randomHex(tokenSecretHex)
	if err != nil {
		return NewToken{}, err
	}
	full := tokenPrefix + idHex + "_" + secret
	rawAllow, _ := json.Marshal(allow)
	now := s.now().UTC()
	t := &store.APIToken{
		ID: ids.New(), LoginID: p.Login.ID, Name: name, Prefix: idHex, Hash: tokenHash(full), Scope: in.Scope,
		IPAllow: string(rawAllow), CreatedAt: now,
	}
	if in.ExpiresDays > 0 {
		e := now.AddDate(0, 0, in.ExpiresDays)
		t.ExpiresAt = &e
	}
	if err := store.InsertToken(ctx, s.db.W, t); err != nil {
		return NewToken{}, err
	}
	if err := s.audit.Record(ctx, s.event(c, p, "auth.token.create", map[string]any{"name": name, "scope": in.Scope, "prefix": idHex})); err != nil {
		return NewToken{}, err
	}
	return NewToken{Token: tokenView(*t), Secret: full}, nil
}

// RevokeToken deletes one of the login's tokens.
func (s *Service) RevokeToken(ctx context.Context, c Client, p *Principal, id string) error {
	t, err := s.db.TokenByID(ctx, id)
	if err != nil {
		return err
	}
	if t.LoginID != p.Login.ID {
		return store.ErrNotFound
	}
	if err := store.DeleteToken(ctx, s.db.W, id); err != nil {
		return err
	}
	return s.audit.Record(ctx, s.event(c, p, "auth.token.revoke", map[string]any{"name": t.Name, "prefix": t.Prefix}))
}

// TokenPrincipal is the caller of a request that carries an API token.
type TokenPrincipal struct {
	*Principal
	Scope string
}

// AuthenticateToken checks a bearer token used from ip. The returned
// principal has a stand-in session that nothing is stored for, so what needs
// a recent password confirmation stays out of a token's reach.
func (s *Service) AuthenticateToken(ctx context.Context, token, ip string) (*TokenPrincipal, error) {
	rest, ok := strings.CutPrefix(token, tokenPrefix)
	if !ok || len(rest) != tokenIDHexLen+1+tokenSecretHex || rest[tokenIDHexLen] != '_' {
		return nil, ErrUnauthenticated
	}
	t, err := s.db.TokenByPrefix(ctx, rest[:tokenIDHexLen])
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrUnauthenticated
	}
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(t.Hash, tokenHash(token)) != 1 {
		return nil, ErrUnauthenticated
	}
	now := s.now()
	if t.ExpiresAt != nil && now.After(*t.ExpiresAt) {
		return nil, ErrUnauthenticated
	}
	var allow []string
	_ = json.Unmarshal([]byte(t.IPAllow), &allow)
	if len(allow) > 0 {
		addr, err := netip.ParseAddr(ip)
		if err != nil || !containsAddr(allow, addr.Unmap()) {
			return nil, ErrTokenIP
		}
	}
	l, err := s.db.LoginByID(ctx, t.LoginID)
	if err != nil || l.Status != store.LoginActive {
		return nil, ErrUnauthenticated
	}
	if t.LastUsedAt == nil || now.Sub(*t.LastUsedAt) > time.Minute {
		_ = s.db.TouchToken(ctx, t.ID, ip, now.UTC())
	}
	sess := &store.Session{IDHash: t.Hash, LoginID: l.ID, MFAPassed: true, IP: ip, CreatedAt: t.CreatedAt, LastSeenAt: now, ExpiresAt: now.Add(time.Minute)}
	return &TokenPrincipal{Principal: &Principal{Login: l, Session: sess}, Scope: t.Scope}, nil
}

func parseNetwork(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return p.Masked(), nil
}

func containsAddr(list []string, a netip.Addr) bool {
	for _, s := range list {
		if p, err := netip.ParsePrefix(s); err == nil && p.Contains(a) {
			return true
		}
	}
	return false
}
