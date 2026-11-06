package server

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/philippe/hauswart/internal/api"
	"github.com/philippe/hauswart/internal/store"
)

// fakeProvider is an identity provider with just enough OIDC for a login.
type fakeProvider struct {
	t      *testing.T
	ts     *httptest.Server
	key    *rsa.PrivateKey
	mu     sync.Mutex
	claims map[string]any
	// audience and nonce replace the real values, to fake a bad token.
	audience, nonce string
	nonces          map[string]string
	// challenge and verifier are what PKCE compares.
	challenges map[string]string
	directory  []directoryUser
	broken     bool
	token      string
}

func newProvider(t *testing.T) *fakeProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProvider{t: t, key: key, nonces: map[string]string{}, challenges: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": p.ts.URL, "authorization_endpoint": p.ts.URL + "/authorize", "token_endpoint": p.ts.URL + "/token",
			"jwks_uri": p.ts.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		p.mu.Lock()
		p.nonces["code-1"] = q.Get("nonce")
		p.challenges["code-1"] = q.Get("code_challenge")
		p.mu.Unlock()
		target := q.Get("redirect_uri") + "?code=code-1&state=" + url.QueryEscape(q.Get("state"))
		http.Redirect(w, r, target, http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		p.mu.Lock()
		defer p.mu.Unlock()
		if base64.RawURLEncoding.EncodeToString(sum[:]) != p.challenges[r.Form.Get("code")] {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "x", "token_type": "Bearer", "id_token": p.idToken(p.nonces[r.Form.Get("code")]),
		})
	})
	mux.HandleFunc("GET /api/v3/core/users/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+p.token || p.broken {
			http.Error(w, "no", http.StatusForbidden)
			return
		}
		// Two pages, to prove that the sync reads them all.
		page := r.URL.Query().Get("page")
		half := len(p.directory) / 2
		out := map[string]any{"pagination": map[string]int{"next": 2}, "results": p.directory[:half]}
		if page == "2" {
			out = map[string]any{"pagination": map[string]int{"next": 0}, "results": p.directory[half:]}
		}
		json.NewEncoder(w).Encode(out)
	})
	p.ts = httptest.NewTLSServer(mux)
	t.Cleanup(p.ts.Close)
	return p
}

func (p *fakeProvider) idToken(nonce string) string {
	if p.nonce != "" {
		nonce = p.nonce
	}
	audience := "hauswart"
	if p.audience != "" {
		audience = p.audience
	}
	claims := map[string]any{
		"iss": p.ts.URL, "aud": audience, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": nonce,
	}
	for key, value := range p.claims {
		claims[key] = value
	}
	encode := func(v any) string {
		raw, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	body := encode(map[string]string{"alg": "RS256", "kid": "k", "typ": "JWT"}) + "." + encode(claims)
	sum := sha256.Sum256([]byte(body))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, sum[:])
	if err != nil {
		p.t.Fatal(err)
	}
	return body + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// oidcEnv is a server with a provider. Its public URL is the test server's.
func oidcEnv(t *testing.T, change func(*OIDCConfig)) (*env, *fakeProvider, *Server) {
	t.Helper()
	e := setup(t)
	p := newProvider(t)
	srv := e.server
	srv.publicURL = e.ts.URL
	cfg := OIDCConfig{Issuer: p.ts.URL, ClientID: "hauswart", ClientSecret: "secret", AdminGroup: "family-admins", ParentGroup: "parents"}
	if change != nil {
		change(&cfg)
	}
	if err := srv.enableOIDC(cfg); err != nil {
		t.Fatal(err)
	}
	// The fake provider has a certificate of its own.
	srv.oidc.client = p.ts.Client()
	return e, p, srv
}

// browser follows everything, as a browser does, and keeps cookies.
func (e *env) browser(p *fakeProvider) *http.Client {
	jar, _ := cookiejar.New(nil)
	c := e.client()
	c.Jar = jar
	transport := c.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.RootCAs.AddCert(p.ts.Certificate())
	c.Transport = transport
	return c
}

func (e *env) oidcLogin(c *http.Client) string {
	e.t.Helper()
	resp, err := c.Get(e.ts.URL + "/auth/oidc/start")
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.Request.URL.Query().Get("login_error")
}

func me(t *testing.T, e *env, c *http.Client) store.User {
	t.Helper()
	code, data := e.do(c, "GET", "/api/me", nil)
	if code != http.StatusOK {
		t.Fatalf("me: %d %s", code, data)
	}
	var u store.User
	json.Unmarshal(data, &u)
	return u
}

func login(p *fakeProvider, subject, username string, groups ...string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.claims = map[string]any{"sub": subject, "preferred_username": username, "groups": groups}
}

func TestOIDCLoginCreatesTheAccount(t *testing.T) {
	e, p, _ := oidcEnv(t, nil)
	login(p, "sub-1", "lena", "parents")
	c := e.browser(p)
	if code := e.oidcLogin(c); code != "" {
		t.Fatalf("login failed: %s", code)
	}
	u := me(t, e, c)
	if u.Username != "lena" || u.LinuxUser != "lena" || u.Role != store.RoleParent || u.Source != "authentik" {
		t.Fatalf("got %+v", u)
	}

	// The groups decide on every login, in both directions.
	login(p, "sub-1", "lena", "family-admins")
	c = e.browser(p)
	e.oidcLogin(c)
	if got := me(t, e, c); got.Role != store.RoleAdmin || got.ID != u.ID {
		t.Fatalf("got %+v", got)
	}
	login(p, "sub-1", "lena")
	c = e.browser(p)
	e.oidcLogin(c)
	if got := me(t, e, c); got.Role != store.RoleMember {
		t.Fatalf("got %+v", got)
	}
}

// Otherwise whoever can pick their name there would become the admin here.
func TestOIDCNeverTakesOverALocalAccount(t *testing.T) {
	e, p, _ := oidcEnv(t, nil)
	login(p, "sub-1", "admin", "family-admins")
	c := e.browser(p)
	if code := e.oidcLogin(c); code != api.ErrOIDCNameTaken {
		t.Fatalf("got %q", code)
	}
	if code, _ := e.do(c, "GET", "/api/me", nil); code != http.StatusUnauthorized {
		t.Fatalf("got %d", code)
	}
}

func TestOIDCRefuses(t *testing.T) {
	cases := map[string]struct {
		prepare func(*fakeProvider)
		code    string
	}{
		"other audience": {func(p *fakeProvider) { p.audience = "someone-else" }, api.ErrOIDCFailed},
		"other nonce":    {func(p *fakeProvider) { p.nonce = "replayed" }, api.ErrOIDCFailed},
		"not a name":     {func(p *fakeProvider) { login(p, "sub-1", "Lena Müller") }, api.ErrOIDCBadName},
		"root":           {func(p *fakeProvider) { login(p, "sub-1", "root") }, api.ErrOIDCBadName},
		"no subject": {func(p *fakeProvider) {
			p.claims = map[string]any{"preferred_username": "lena"}
		}, api.ErrOIDCFailed},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e, p, _ := oidcEnv(t, nil)
			login(p, "sub-1", "lena")
			c.prepare(p)
			client := e.browser(p)
			if got := e.oidcLogin(client); got != c.code {
				t.Fatalf("got %q", got)
			}
			if code, _ := e.do(client, "GET", "/api/me", nil); code != http.StatusUnauthorized {
				t.Fatalf("logged in: %d", code)
			}
		})
	}
}

func TestOIDCAllowedGroup(t *testing.T) {
	e, p, _ := oidcEnv(t, func(c *OIDCConfig) { c.AllowedGroup = "family" })
	login(p, "sub-1", "lena", "friends")
	if got := e.oidcLogin(e.browser(p)); got != api.ErrOIDCNotAllowed {
		t.Fatalf("got %q", got)
	}
	login(p, "sub-1", "lena", "family")
	if got := e.oidcLogin(e.browser(p)); got != "" {
		t.Fatalf("got %q", got)
	}
}

// Login CSRF: an attacker must not be able to log a victim into their account.
func TestOIDCAnswerBelongsToTheBrowserThatAsked(t *testing.T) {
	e, p, _ := oidcEnv(t, nil)
	login(p, "sub-1", "lena")

	attacker := e.browser(p)
	attacker.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		if strings.Contains(req.URL.Path, "/callback") {
			return http.ErrUseLastResponse
		}
		return nil
	}
	resp, err := attacker.Get(e.ts.URL + "/auth/oidc/start")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	callback := resp.Header.Get("Location")

	victim := e.browser(p)
	got, err := victim.Get(callback)
	if err != nil {
		t.Fatal(err)
	}
	got.Body.Close()
	if code := got.Request.URL.Query().Get("login_error"); code != api.ErrOIDCFailed {
		t.Fatalf("got %q", code)
	}
	if code, _ := e.do(victim, "GET", "/api/me", nil); code != http.StatusUnauthorized {
		t.Fatalf("logged in: %d", code)
	}
}

func TestOIDCAttemptWorksOnce(t *testing.T) {
	_, _, srv := oidcEnv(t, nil)
	now := time.Now()
	srv.oidc.remember("state", oidcAttempt{expires: now.Add(time.Minute)}, now)
	if _, ok := srv.oidc.take("state", now); !ok {
		t.Fatal("refused the first use")
	}
	if _, ok := srv.oidc.take("state", now); ok {
		t.Fatal("accepted the second use")
	}
	srv.oidc.remember("old", oidcAttempt{expires: now.Add(time.Minute)}, now)
	if _, ok := srv.oidc.take("old", now.Add(time.Hour)); ok {
		t.Fatal("accepted an expired attempt")
	}
}

func TestAuthentikAccountsCannotBeChangedHere(t *testing.T) {
	e, p, _ := oidcEnv(t, nil)
	login(p, "sub-1", "lena")
	c := e.browser(p)
	e.oidcLogin(c)
	id := me(t, e, c).ID
	admin := e.login("admin")
	path := fmt.Sprintf("/api/users/%d", id)
	if code, data := e.do(admin, "PUT", path+"/role", map[string]string{"role": "admin"}); code != http.StatusConflict {
		t.Fatalf("%d %s", code, data)
	}
	if code, data := e.do(admin, "DELETE", path, nil); code != http.StatusConflict {
		t.Fatalf("%d %s", code, data)
	}
	if code, data := e.do(c, "POST", "/api/password", map[string]string{"old": "x", "new": "y"}); code != http.StatusConflict {
		t.Fatalf("%d %s", code, data)
	}
	// No password opens this account, not even an empty one.
	if code, _ := e.do(e.client(), "POST", "/api/login", map[string]string{"username": "lena", "password": ""}); code != http.StatusUnauthorized {
		t.Fatalf("got %d", code)
	}
	if code, _ := e.do(e.client(), "POST", "/api/login", map[string]string{"username": "lena", "password": "!"}); code != http.StatusUnauthorized {
		t.Fatalf("got %d", code)
	}
}

func TestLocalAdminStaysAsEmergencyAccess(t *testing.T) {
	e, _, srv := oidcEnv(t, nil)
	srv.oidc.cfg.Issuer = "https://127.0.0.1:1/nowhere"
	e.login("admin")
	_, data := e.do(e.client(), "GET", "/api/login-options", nil)
	if !strings.Contains(string(data), `"oidc":true`) {
		t.Fatalf("got %s", data)
	}
}

func directoryEntry(uid, name string, active bool, groups ...string) directoryUser {
	list := []struct {
		Name string `json:"name"`
	}{}
	for _, group := range groups {
		list = append(list, struct {
			Name string `json:"name"`
		}{group})
	}
	return directoryUser{UID: uid, Username: name, Active: &active, Type: directoryInternal, Groups: &list}
}

func syncEnv(t *testing.T) (*env, *fakeProvider, *Server) {
	t.Helper()
	var p *fakeProvider
	e, p, srv := oidcEnv(t, nil)
	p.token = "api-token"
	srv.oidc.cfg.DirectoryURL = p.ts.URL
	srv.oidc.cfg.DirectoryToken = p.token
	return e, p, srv
}

func listed(t *testing.T, e *env) map[string]store.User {
	t.Helper()
	users, err := e.store.ListUsers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]store.User{}
	for _, u := range users {
		byName[u.Username] = u
	}
	return byName
}

func TestSyncBringsAccountsOver(t *testing.T) {
	e, p, srv := syncEnv(t)
	bot := directoryEntry("sub-3", "outpost", true)
	bot.Type = "internal_service_account"
	p.directory = []directoryUser{
		directoryEntry("sub-1", "lena", true, "parents"),
		directoryEntry("sub-2", "max", true),
		bot,
		directoryEntry("sub-4", "Not A Name", true),
	}
	srv.syncDirectory(context.Background())
	users := listed(t, e)
	if users["lena"].Role != store.RoleParent || users["max"].Role != store.RoleMember || users["lena"].Source != "authentik" {
		t.Fatalf("got %+v", users)
	}
	if _, ok := users["outpost"]; ok {
		t.Fatal("a service account became a user")
	}
	if _, ok := users["Not A Name"]; ok {
		t.Fatal("an unusable name became a user")
	}
	if users["admin"].Disabled || users["anna"].Disabled {
		t.Fatal("touched local accounts")
	}
}

func TestSyncEndsAccess(t *testing.T) {
	e, p, srv := syncEnv(t)
	login(p, "sub-1", "lena")
	p.directory = []directoryUser{directoryEntry("sub-1", "lena", true), directoryEntry("sub-2", "max", true)}
	srv.syncDirectory(context.Background())
	c := e.browser(p)
	e.oidcLogin(c)
	me(t, e, c)

	p.directory = []directoryUser{directoryEntry("sub-1", "lena", false), directoryEntry("sub-2", "max", true)}
	srv.syncDirectory(context.Background())
	if code, _ := e.do(c, "GET", "/api/me", nil); code != http.StatusUnauthorized {
		t.Fatalf("a disabled user is still logged in: %d", code)
	}
	if got := e.oidcLogin(e.browser(p)); got != api.ErrOIDCNotAllowed {
		t.Fatalf("got %q", got)
	}

	p.directory = []directoryUser{directoryEntry("sub-1", "lena", true), directoryEntry("sub-2", "max", true)}
	srv.syncDirectory(context.Background())
	if got := e.oidcLogin(e.browser(p)); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestProviderAwayChangesNothing(t *testing.T) {
	e, p, srv := syncEnv(t)
	p.directory = []directoryUser{directoryEntry("sub-1", "lena", true), directoryEntry("sub-2", "max", true)}
	srv.syncDirectory(context.Background())
	p.broken = true
	srv.syncDirectory(context.Background())
	if listed(t, e)["lena"].Disabled {
		t.Fatal("a failed sync disabled someone")
	}
}

func TestOIDCConfigChecks(t *testing.T) {
	good := OIDCConfig{Issuer: "https://a", ClientID: "x", ClientSecret: "y", AdminGroup: "z"}
	if err := good.check(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*OIDCConfig){
		"plain http":    func(c *OIDCConfig) { c.Issuer = "http://a" },
		"no secret":     func(c *OIDCConfig) { c.ClientSecret = "" },
		"no admins":     func(c *OIDCConfig) { c.AdminGroup = "" },
		"token only":    func(c *OIDCConfig) { c.DirectoryToken = "t" },
		"sync on plain": func(c *OIDCConfig) { c.DirectoryURL, c.DirectoryToken = "http://a", "t" },
	} {
		cfg := good
		change(&cfg)
		if cfg.check() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestBadAnswersChangeNothing(t *testing.T) {
	noGroups := directoryEntry("sub-1", "lena", true)
	noGroups.Groups = nil
	noState := directoryEntry("sub-1", "lena", true)
	noState.Active = nil
	noSubject := directoryEntry("", "admin", true)
	for name, answer := range map[string][]directoryUser{
		"empty":      {},
		"no groups":  {noGroups, directoryEntry("sub-2", "max", true)},
		"no state":   {noState, directoryEntry("sub-2", "max", true)},
		"no subject": {noSubject, directoryEntry("sub-1", "lena", true, "family-admins")},
	} {
		t.Run(name, func(t *testing.T) {
			e, p, srv := syncEnv(t)
			p.directory = []directoryUser{directoryEntry("sub-1", "lena", true, "family-admins"), directoryEntry("sub-2", "max", true)}
			srv.syncDirectory(context.Background())
			p.directory = answer
			srv.syncDirectory(context.Background())
			users := listed(t, e)
			if users["lena"].Disabled || users["lena"].Role != store.RoleAdmin || users["admin"].Source != "" {
				t.Fatalf("got %+v", users)
			}
		})
	}
}

func TestLocalAccountsCannotBeFoundWithoutASubject(t *testing.T) {
	e := setup(t)
	if _, err := e.store.SaveDirectoryUser(context.Background(), store.DirectoryUser{Username: "mia", Role: store.RoleMember}); err == nil {
		t.Fatal("saved an account without a subject")
	}
	if users := listed(t, e); users["admin"].Role != store.RoleAdmin {
		t.Fatalf("got %+v", users)
	}
}

func TestNamesCanMoveInTheDirectory(t *testing.T) {
	e, p, srv := syncEnv(t)
	p.directory = []directoryUser{directoryEntry("sub-1", "lena", true), directoryEntry("sub-2", "max", true)}
	srv.syncDirectory(context.Background())

	// They swap.
	p.directory = []directoryUser{directoryEntry("sub-1", "max", true), directoryEntry("sub-2", "lena", true)}
	srv.syncDirectory(context.Background())
	users := listed(t, e)
	if users["lena"].Disabled || users["max"].Disabled {
		t.Fatalf("got %+v", users)
	}

	// Someone is deleted and comes back with a new subject.
	p.directory = []directoryUser{directoryEntry("sub-3", "lena", true), directoryEntry("sub-1", "max", true)}
	srv.syncDirectory(context.Background())
	if users := listed(t, e); users["lena"].Disabled {
		t.Fatalf("got %+v", users)
	}
}

func TestLastWorkingAdminIsKept(t *testing.T) {
	e, p, srv := syncEnv(t)
	ctx := context.Background()
	p.directory = []directoryUser{directoryEntry("sub-1", "lena", true, "family-admins"), directoryEntry("sub-2", "max", true)}
	srv.syncDirectory(ctx)
	p.directory = []directoryUser{directoryEntry("sub-1", "lena", false, "family-admins"), directoryEntry("sub-2", "max", true)}
	srv.syncDirectory(ctx)
	if !listed(t, e)["lena"].Disabled {
		t.Fatal("the local admin is there, so lena can go")
	}
	id := listed(t, e)["admin"].ID
	if err := e.store.DeleteUser(ctx, id); err == nil {
		t.Fatal("removed the only admin who can still log in")
	}
}
