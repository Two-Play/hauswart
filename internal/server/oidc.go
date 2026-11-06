package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/philippe/hauswart/internal/api"
	"github.com/philippe/hauswart/internal/envfile"
	"github.com/philippe/hauswart/internal/store"
)

const (
	oidcCookie      = "hauswart_oidc"
	oidcCookiePath  = "/auth/oidc/"
	oidcAttemptTTL  = 10 * time.Minute
	maxOIDCAttempts = 200
	oidcTimeout     = 20 * time.Second
	directoryPages  = 100
	directoryLimit  = 8 << 20
	// directoryAccounts are the kinds of account that are people.
	directoryInternal = "internal"
	directoryExternal = "external"
)

func init() {
	addRoutes(func(s *Server, mux *http.ServeMux) {
		mux.HandleFunc("GET /api/login-options", s.handleLoginOptions)
		mux.HandleFunc("GET /auth/oidc/start", s.handleOIDCStart)
		mux.HandleFunc("GET /auth/oidc/callback", s.handleOIDCCallback)
	})
}

// OIDCConfig holds the settings of the identity provider.
type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	// AdminGroup and ParentGroup give those roles. Everyone else is a member.
	AdminGroup  string
	ParentGroup string
	// AllowedGroup limits who may log in at all, if set.
	AllowedGroup string
	// CAFile is for a provider whose certificate comes from elsewhere.
	CAFile string
	// DirectoryURL and DirectoryToken turn on the sync of accounts.
	DirectoryURL   string
	DirectoryToken string
}

func (c *OIDCConfig) set(key, value string) bool {
	target := map[string]*string{
		"OIDC_ISSUER":        &c.Issuer,
		"OIDC_CLIENT_ID":     &c.ClientID,
		"OIDC_CLIENT_SECRET": &c.ClientSecret,
		"OIDC_ADMIN_GROUP":   &c.AdminGroup,
		"OIDC_PARENT_GROUP":  &c.ParentGroup,
		"OIDC_ALLOWED_GROUP": &c.AllowedGroup,
		"OIDC_CA_FILE":       &c.CAFile,
		"AUTHENTIK_URL":      &c.DirectoryURL,
		"AUTHENTIK_TOKEN":    &c.DirectoryToken,
	}[key]
	if target == nil {
		return false
	}
	*target = value
	return true
}

func (c OIDCConfig) check() error {
	if !strings.HasPrefix(c.Issuer, "https://") {
		return errors.New("OIDC_ISSUER must use https")
	}
	if c.ClientID == "" || c.ClientSecret == "" {
		return errors.New("OIDC_CLIENT_ID and OIDC_CLIENT_SECRET are required")
	}
	// An empty group would match nobody, and silently leave only members.
	if c.AdminGroup == "" {
		return errors.New("OIDC_ADMIN_GROUP is required")
	}
	if (c.DirectoryURL == "") != (c.DirectoryToken == "") {
		return errors.New("AUTHENTIK_URL and AUTHENTIK_TOKEN go together")
	}
	if c.DirectoryURL != "" && !strings.HasPrefix(c.DirectoryURL, "https://") {
		return errors.New("AUTHENTIK_URL must use https")
	}
	return nil
}

// oidcAttempt is one login on its way through the provider.
type oidcAttempt struct {
	nonce    string
	verifier string
	expires  time.Time
}

type oidcLogin struct {
	cfg    OIDCConfig
	client *http.Client

	mu       sync.Mutex
	attempts map[string]oidcAttempt
	provider *oidc.Provider
}

// StartOIDC reads the settings. Anything wrong keeps the feature off and leaves
// the local login, which is what an admin needs to find out why.
func (s *Server) StartOIDC(path string) {
	var cfg OIDCConfig
	found, err := envfile.Read(path, cfg.set)
	if err == nil && found {
		err = cfg.check()
	}
	if err != nil {
		s.log.Error("login through Authentik is off", "err", err)
		return
	}
	if !found {
		return
	}
	if err := s.enableOIDC(cfg); err != nil {
		s.log.Error("login through Authentik is off", "err", err)
		return
	}
	s.log.Info("login through Authentik is on", "issuer", cfg.Issuer, "sync", cfg.DirectoryURL != "")
}

func (s *Server) enableOIDC(cfg OIDCConfig) error {
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	roots.AddCert(s.ca.Cert)
	if cfg.CAFile != "" {
		raw, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return err
		}
		if !roots.AppendCertsFromPEM(raw) {
			return fmt.Errorf("%s holds no certificate", cfg.CAFile)
		}
	}
	s.oidc = &oidcLogin{
		cfg:      cfg,
		attempts: map[string]oidcAttempt{},
		client: &http.Client{
			Timeout:   oidcTimeout,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
		},
	}
	return nil
}

func (s *Server) handleLoginOptions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"oidc": s.oidc != nil})
}

// discover looks the provider up at the first login, so that a server starts
// while the provider is away. A failed attempt is simply repeated by the next.
func (o *oidcLogin) discover(ctx context.Context) (*oidc.Provider, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.provider != nil {
		return o.provider, nil
	}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, o.client), o.cfg.Issuer)
	if err != nil {
		return nil, err
	}
	o.provider = provider
	return provider, nil
}

func (s *Server) oauthConfig(provider *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     s.oidc.cfg.ClientID,
		ClientSecret: s.oidc.cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  s.publicURL + oidcCookiePath + "callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
}

func randomValue() string {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		panic(err) // crypto/rand failing is not recoverable
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// remember keeps an attempt. Anyone can start one, so the number is limited, and
// old attempts make room.
func (o *oidcLogin) remember(state string, attempt oidcAttempt, now time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for key, known := range o.attempts {
		if now.After(known.expires) {
			delete(o.attempts, key)
		}
	}
	if len(o.attempts) >= maxOIDCAttempts {
		for key := range o.attempts {
			delete(o.attempts, key)
			break
		}
	}
	o.attempts[state] = attempt
}

// take hands out an attempt once.
func (o *oidcLogin) take(state string, now time.Time) (oidcAttempt, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	attempt, ok := o.attempts[state]
	delete(o.attempts, state)
	return attempt, ok && now.Before(attempt.expires)
}

func (s *Server) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		http.NotFound(w, r)
		return
	}
	provider, err := s.oidc.discover(r.Context())
	if err != nil {
		s.log.Warn("the identity provider cannot be reached", "err", err)
		loginFailed(w, r, api.ErrOIDCFailed)
		return
	}
	state, nonce, verifier := randomValue(), randomValue(), oauth2.GenerateVerifier()
	s.oidc.remember(state, oidcAttempt{nonce: nonce, verifier: verifier, expires: time.Now().Add(oidcAttemptTTL)}, time.Now())
	// Lax, because the way back comes from another site. The cookie ties the
	// answer to this browser, so that nobody can log a victim into their account.
	http.SetCookie(w, &http.Cookie{
		Name: oidcCookie, Value: state, Path: oidcCookiePath, MaxAge: int(oidcAttemptTTL.Seconds()),
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode,
	})
	target := s.oauthConfig(provider).AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, r, target, http.StatusFound)
}

func loginFailed(w http.ResponseWriter, r *http.Request, code string) {
	http.Redirect(w, r, "/?login_error="+url.QueryEscape(code), http.StatusFound)
}

// oidcClaims are the parts of an ID token that matter here.
type oidcClaims struct {
	Username string   `json:"preferred_username"`
	Groups   []string `json:"groups"`
}

func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		http.NotFound(w, r)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Path: oidcCookiePath, MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
	state := r.URL.Query().Get("state")
	cookie, err := r.Cookie(oidcCookie)
	if err != nil || state == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		s.audit(r, "", "login.oidc.refused", "state does not match")
		loginFailed(w, r, api.ErrOIDCFailed)
		return
	}
	attempt, ok := s.oidc.take(state, time.Now())
	if !ok {
		s.audit(r, "", "login.oidc.refused", "unknown or expired state")
		loginFailed(w, r, api.ErrOIDCFailed)
		return
	}
	subject, claims, err := s.exchange(r, attempt)
	if err != nil {
		s.log.Warn("login through the identity provider failed", "err", err)
		s.audit(r, "", "login.oidc.refused", "token refused")
		loginFailed(w, r, api.ErrOIDCFailed)
		return
	}

	directory := store.DirectoryUser{Subject: subject, Username: claims.Username, Role: s.oidc.role(claims.Groups)}
	if code := s.oidc.refuse(directory.Username, claims.Groups); code != "" {
		s.audit(r, claims.Username, "login.oidc.refused", code)
		loginFailed(w, r, code)
		return
	}
	u, err := s.store.SaveDirectoryUser(r.Context(), directory)
	if errors.Is(err, store.ErrNameTaken) {
		s.audit(r, claims.Username, "login.oidc.refused", api.ErrOIDCNameTaken)
		loginFailed(w, r, api.ErrOIDCNameTaken)
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	if u.Disabled {
		s.audit(r, u.Username, "login.oidc.refused", "disabled")
		loginFailed(w, r, api.ErrOIDCNotAllowed)
		return
	}
	token, err := s.store.CreateSession(r.Context(), u.ID, sessionTTL)
	if err != nil {
		s.internal(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", MaxAge: int(sessionTTL.Seconds()),
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode,
	})
	s.audit(r, u.Username, "login.oidc", clientIP(r))
	http.Redirect(w, r, "/", http.StatusFound)
}

// exchange turns the code from the browser into verified claims.
func (s *Server) exchange(r *http.Request, attempt oidcAttempt) (string, oidcClaims, error) {
	var claims oidcClaims
	if problem := r.URL.Query().Get("error"); problem != "" {
		return "", claims, fmt.Errorf("the provider said %q: %q", clip(problem), clip(r.URL.Query().Get("error_description")))
	}
	ctx := oidc.ClientContext(r.Context(), s.oidc.client)
	provider, err := s.oidc.discover(ctx)
	if err != nil {
		return "", claims, err
	}
	token, err := s.oauthConfig(provider).Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(attempt.verifier))
	if err != nil {
		return "", claims, err
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		return "", claims, errors.New("no ID token")
	}
	verified, err := provider.Verifier(&oidc.Config{ClientID: s.oidc.cfg.ClientID}).Verify(ctx, raw)
	if err != nil {
		return "", claims, err
	}
	if subtle.ConstantTimeCompare([]byte(verified.Nonce), []byte(attempt.nonce)) != 1 {
		return "", claims, errors.New("the nonce does not match")
	}
	if err := verified.Claims(&claims); err != nil {
		return "", claims, err
	}
	if verified.Subject == "" {
		return "", claims, errors.New("no subject")
	}
	return verified.Subject, claims, nil
}

func clip(s string) string {
	if len(s) > 100 {
		return s[:100]
	}
	return s
}

func (o *oidcLogin) role(groups []string) string {
	switch {
	case slices.Contains(groups, o.cfg.AdminGroup):
		return store.RoleAdmin
	case o.cfg.ParentGroup != "" && slices.Contains(groups, o.cfg.ParentGroup):
		return store.RoleParent
	}
	return store.RoleMember
}

// refuse says why someone may not have an account here, as an error code.
func (o *oidcLogin) refuse(username string, groups []string) string {
	if o.cfg.AllowedGroup != "" && !slices.Contains(groups, o.cfg.AllowedGroup) {
		return api.ErrOIDCNotAllowed
	}
	// The name becomes the Linux account of this person.
	if !api.ValidUser(username) {
		return api.ErrOIDCBadName
	}
	return ""
}

// managedElsewhere refuses changes to an account the next sync would undo.
func (s *Server) managedElsewhere(w http.ResponseWriter, r *http.Request, id int64) bool {
	source, err := s.store.UserSource(r.Context(), id)
	if err != nil || source == "" {
		return false // a missing account gets its usual answer from the caller
	}
	fail(w, http.StatusConflict, api.ErrManagedElsewhere)
	return true
}

// directoryUser is the part of Authentik's user API that matters here. Its uid
// is what ID tokens carry as the subject in the default setting.
type directoryUser struct {
	UID      string `json:"uid"`
	Username string `json:"username"`
	Active   bool   `json:"is_active"`
	Type     string `json:"type"`
	Groups   []struct {
		Name string `json:"name"`
	} `json:"groups_obj"`
}

func (s *Server) fetchDirectory(ctx context.Context) ([]directoryUser, error) {
	cfg := s.oidc.cfg
	var users []directoryUser
	for page := 1; page > 0; {
		target := fmt.Sprintf("%s/api/v3/core/users/?page=%d&page_size=%d", strings.TrimRight(cfg.DirectoryURL, "/"), page, directoryPages)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+cfg.DirectoryToken)
		resp, err := s.oidc.client.Do(req)
		if err != nil {
			return nil, err
		}
		var out struct {
			Pagination struct {
				Next int `json:"next"`
			} `json:"pagination"`
			Results []directoryUser `json:"results"`
		}
		err = func() error {
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("status %d", resp.StatusCode)
			}
			return json.NewDecoder(io.LimitReader(resp.Body, directoryLimit)).Decode(&out)
		}()
		if err != nil {
			return nil, err
		}
		users = append(users, out.Results...)
		page = out.Pagination.Next
	}
	return users, nil
}

// syncDirectory brings the accounts up to date. Failing to reach the provider
// changes nothing: a provider that is away says nothing about anyone.
func (s *Server) syncDirectory(ctx context.Context) {
	if s.oidc == nil || s.oidc.cfg.DirectoryURL == "" {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, oidcTimeout)
	defer cancel()
	users, err := s.fetchDirectory(ctx)
	if err != nil {
		s.log.Warn("the sync of accounts failed", "err", err)
		return
	}
	present := map[string]bool{}
	for _, user := range users {
		if user.Type != directoryInternal && user.Type != directoryExternal {
			continue
		}
		var groups []string
		for _, group := range user.Groups {
			groups = append(groups, group.Name)
		}
		if !user.Active || s.oidc.refuse(user.Username, groups) != "" {
			continue
		}
		_, err := s.store.SaveDirectoryUser(ctx, store.DirectoryUser{Subject: user.UID, Username: user.Username, Role: s.oidc.role(groups)})
		if err != nil {
			s.log.Warn("an account could not be synced", "user", user.Username, "err", err)
			continue
		}
		present[user.UID] = true
	}
	known, err := s.store.DirectorySubjects(ctx)
	if err != nil {
		s.log.Warn("the sync of accounts failed", "err", err)
		return
	}
	for _, subject := range known {
		if err := s.store.SetDirectoryUserDisabled(ctx, subject, !present[subject]); err != nil {
			s.log.Warn("an account could not be synced", "err", err)
		}
	}
}
