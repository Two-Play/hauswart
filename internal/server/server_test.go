package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GehirnInc/crypt/sha512_crypt"

	"github.com/philippe/hauswart/internal/api"
	"github.com/philippe/hauswart/internal/pki"
	"github.com/philippe/hauswart/internal/store"
)

const testPassword = "correct horse battery"

type env struct {
	t     *testing.T
	ts    *httptest.Server
	store *store.Store
	ca    *pki.CA
}

func setup(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	ca, err := pki.LoadOrCreate(filepath.Join(dir, "pki"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv, err := New(st, ca, "https://test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := srv.TLSConfig([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(srv.Handler())
	ts.TLS = cfg
	ts.StartTLS()
	t.Cleanup(ts.Close)

	hash, err := HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := st.CreateUser(ctx, "admin", "admin", hash, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(ctx, "anna", "anna", hash, "member"); err != nil {
		t.Fatal(err)
	}
	return &env{t: t, ts: ts, store: st, ca: ca}
}

func (e *env) client(certs ...tls.Certificate) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar: jar,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:      e.ca.Pool(),
			Certificates: certs,
		}},
	}
}

func (e *env) do(c *http.Client, method, path string, body any) (int, []byte) {
	e.t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		e.t.Fatal(err)
	}
	req, err := http.NewRequest(method, e.ts.URL+path, bytes.NewReader(raw))
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("X-Hauswart", "1")
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

func (e *env) login(name string) *http.Client {
	e.t.Helper()
	c := e.client()
	code, data := e.do(c, "POST", "/api/login", map[string]string{"username": name, "password": testPassword})
	if code != http.StatusOK {
		e.t.Fatalf("login: %d %s", code, data)
	}
	return c
}

// enroll runs a real enrollment and returns the device ID and a client
// carrying its certificate.
func (e *env) enroll() (string, *http.Client) {
	e.t.Helper()
	token, err := e.store.CreateEnrollToken(context.Background(), 60_000_000_000)
	if err != nil {
		e.t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		e.t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "admin"}}, key)
	if err != nil {
		e.t.Fatal(err)
	}
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	code, data := e.do(e.client(), "POST", "/agent/enroll", api.EnrollRequest{Token: token, CSR: string(csr), Hostname: "laptop"})
	if code != http.StatusOK {
		e.t.Fatalf("enroll: %d %s", code, data)
	}
	var out api.EnrollResponse
	if err := json.Unmarshal(data, &out); err != nil {
		e.t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	cert, err := tls.X509KeyPair([]byte(out.Cert), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		e.t.Fatal(err)
	}
	return out.DeviceID, e.client(cert)
}

func TestIndexGetsFreshNonce(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	srv := &Server{store: st, index: []byte(`<meta content="` + noncePlaceholder + `">`)}

	fetch := func() (csp, body string) {
		rec := httptest.NewRecorder()
		srv.handleIndex(rec, httptest.NewRequest("GET", "/", nil))
		return rec.Header().Get("Content-Security-Policy"), rec.Body.String()
	}
	csp, body := fetch()
	if strings.Contains(body, noncePlaceholder) {
		t.Fatal("placeholder not replaced")
	}
	nonce := strings.TrimSuffix(strings.TrimPrefix(body, `<meta content="`), `">`)
	if !strings.Contains(csp, "'nonce-"+nonce+"'") {
		t.Fatalf("CSP %q does not carry nonce %q", csp, nonce)
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Fatal("CSP allows inline styles")
	}
	if _, second := fetch(); second == body {
		t.Fatal("nonce reused")
	}
}

func TestIndexWithoutBuild(t *testing.T) {
	srv := &Server{}
	rec := httptest.NewRecorder()
	srv.handleIndex(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestChangePassword(t *testing.T) {
	e := setup(t)
	first, second := e.login("anna"), e.login("anna")
	change := func(c *http.Client, current, next string) int {
		code, _ := e.do(c, "POST", "/api/password", map[string]string{"current": current, "new": next})
		return code
	}
	if code := change(first, "wrong", "a new long password"); code != http.StatusForbidden {
		t.Fatalf("wrong current: %d", code)
	}
	if code := change(first, testPassword, "short"); code != http.StatusBadRequest {
		t.Fatalf("short: %d", code)
	}
	if code := change(first, testPassword, "a new long password"); code != http.StatusNoContent {
		t.Fatalf("change: %d", code)
	}
	if code, _ := e.do(first, "GET", "/api/me", nil); code != http.StatusOK {
		t.Fatalf("own session ended: %d", code)
	}
	if code, _ := e.do(second, "GET", "/api/me", nil); code != http.StatusUnauthorized {
		t.Fatalf("other session survived: %d", code)
	}
	code, _ := e.do(e.client(), "POST", "/api/login", map[string]string{"username": "anna", "password": "a new long password"})
	if code != http.StatusOK {
		t.Fatalf("login with new password: %d", code)
	}
}

func TestLastAdminCannotBeRemoved(t *testing.T) {
	e := setup(t)
	admin := e.login("admin")
	var users []store.User
	_, data := e.do(admin, "GET", "/api/users", nil)
	json.Unmarshal(data, &users)
	ids := map[string]int64{}
	for _, u := range users {
		ids[u.Username] = u.ID
	}
	if code, _ := e.do(e.login("anna"), "DELETE", fmt.Sprintf("/api/users/%d", ids["admin"]), nil); code != http.StatusForbidden {
		t.Fatalf("member removed a user: %d", code)
	}
	if code, _ := e.do(admin, "DELETE", fmt.Sprintf("/api/users/%d", ids["admin"]), nil); code != http.StatusConflict {
		t.Fatalf("last admin: %d", code)
	}
	if code, _ := e.do(admin, "DELETE", fmt.Sprintf("/api/users/%d", ids["anna"]), nil); code != http.StatusNoContent {
		t.Fatalf("member: %d", code)
	}
}

func TestStartPasswordStaysSecret(t *testing.T) {
	e := setup(t)
	id, agent := e.enroll()
	admin := e.login("admin")

	code, data := e.do(admin, "POST", "/api/devices/"+id+"/start-password", map[string]string{"user": "anna"})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, data)
	}
	var out struct{ Password string }
	json.Unmarshal(data, &out)
	if len(out.Password) != startPasswordLen {
		t.Fatalf("password %q", out.Password)
	}

	code, data = e.do(agent, "GET", "/agent/tasks?wait=0", nil)
	if code != http.StatusOK {
		t.Fatalf("poll: %d", code)
	}
	var task api.Task
	json.Unmarshal(data, &task)
	var payload api.PasswordPayload
	json.Unmarshal(task.Payload, &payload)
	if err := sha512_crypt.New().Verify(payload.Hash, []byte(out.Password)); err != nil {
		t.Fatalf("hash does not match the password: %v", err)
	}

	for _, path := range []string{"/api/tasks", "/api/audit"} {
		_, body := e.do(admin, "GET", path, nil)
		if strings.Contains(string(body), payload.Hash) || strings.Contains(string(body), out.Password) {
			t.Errorf("%s leaks the password or its hash", path)
		}
	}
}

func TestStartPasswordOnlyThroughItsRoute(t *testing.T) {
	e := setup(t)
	id, _ := e.enroll()
	admin := e.login("admin")
	in := map[string]any{"type": api.TaskUserPassword, "payload": api.PasswordPayload{User: "anna", Hash: "$6$s$" + strings.Repeat("a", 86)}}
	if code, _ := e.do(admin, "POST", "/api/devices/"+id+"/tasks", in); code != http.StatusBadRequest {
		t.Fatalf("got %d", code)
	}
	if code, _ := e.do(admin, "POST", "/api/devices/"+id+"/start-password", map[string]string{"user": "root"}); code != http.StatusBadRequest {
		t.Fatalf("root: %d", code)
	}
	if code, _ := e.do(e.login("anna"), "POST", "/api/devices/"+id+"/start-password", map[string]string{"user": "anna"}); code != http.StatusForbidden {
		t.Fatalf("member: %d", code)
	}
}

func TestLogin(t *testing.T) {
	e := setup(t)
	code, _ := e.do(e.client(), "POST", "/api/login", map[string]string{"username": "admin", "password": "wrong"})
	if code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", code)
	}
	code, _ = e.do(e.client(), "GET", "/api/me", nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", code)
	}
	if code, _ := e.do(e.login("admin"), "GET", "/api/me", nil); code != http.StatusOK {
		t.Fatalf("session: %d", code)
	}
}

func TestLoginLockout(t *testing.T) {
	e := setup(t)
	c := e.client()
	for range maxLoginFails {
		e.do(c, "POST", "/api/login", map[string]string{"username": "admin", "password": "wrong"})
	}
	code, _ := e.do(c, "POST", "/api/login", map[string]string{"username": "admin", "password": testPassword})
	if code != http.StatusTooManyRequests {
		t.Fatalf("got %d", code)
	}
}

func TestCSRFHeaderRequired(t *testing.T) {
	e := setup(t)
	c := e.login("admin")
	req, _ := http.NewRequest("POST", e.ts.URL+"/api/enroll-tokens", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("got %d", resp.StatusCode)
	}
}

func TestMemberCannotUseAdminRoutes(t *testing.T) {
	e := setup(t)
	id, _ := e.enroll()
	member := e.login("anna")
	routes := []struct{ method, path string }{
		{"POST", "/api/enroll-tokens"},
		{"POST", "/api/devices/" + id + "/tasks"},
		{"POST", "/api/devices/" + id + "/revoke"},
		{"GET", "/api/tasks"},
		{"GET", "/api/users"},
		{"POST", "/api/users"},
		{"GET", "/api/audit"},
		{"POST", "/api/requests/x/approve"},
		{"POST", "/api/requests/x/deny"},
	}
	for _, r := range routes {
		if code, _ := e.do(member, r.method, r.path, map[string]any{}); code != http.StatusForbidden {
			t.Errorf("%s %s: %d", r.method, r.path, code)
		}
	}
}

func TestEnrollTokenWorksOnce(t *testing.T) {
	e := setup(t)
	token, _ := e.store.CreateEnrollToken(context.Background(), 60_000_000_000)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	in := api.EnrollRequest{Token: token, CSR: csr, Hostname: "a"}
	if code, data := e.do(e.client(), "POST", "/agent/enroll", in); code != http.StatusOK {
		t.Fatalf("first: %d %s", code, data)
	}
	if code, _ := e.do(e.client(), "POST", "/agent/enroll", in); code != http.StatusForbidden {
		t.Fatalf("second: %d", code)
	}
}

func TestAgentRoutesNeedValidCertificate(t *testing.T) {
	e := setup(t)
	if code, _ := e.do(e.client(), "GET", "/agent/tasks?wait=0", nil); code != http.StatusUnauthorized {
		t.Fatalf("no certificate: %d", code)
	}
	id, agent := e.enroll()
	if code, _ := e.do(agent, "GET", "/agent/tasks?wait=0", nil); code != http.StatusNoContent {
		t.Fatalf("enrolled: %d", code)
	}
	if code, _ := e.do(e.login("admin"), "POST", "/api/devices/"+id+"/revoke", nil); code != http.StatusNoContent {
		t.Fatalf("revoke: %d", code)
	}
	agent.CloseIdleConnections()
	if code, _ := e.do(agent, "GET", "/agent/tasks?wait=0", nil); code != http.StatusForbidden {
		t.Fatalf("revoked: %d", code)
	}
}

func TestDeviceIdentityComesFromServer(t *testing.T) {
	e := setup(t)
	id, _ := e.enroll()
	// The test CSR asks for the CN "admin"; the server must have ignored it.
	if id == "admin" || len(id) != 32 {
		t.Fatalf("device chose its own identity: %q", id)
	}
}

func TestDeviceCannotFinishForeignTask(t *testing.T) {
	e := setup(t)
	idA, agentA := e.enroll()
	_, agentB := e.enroll()
	admin := e.login("admin")
	code, data := e.do(admin, "POST", "/api/devices/"+idA+"/tasks", map[string]any{"type": api.TaskPkgUpgrade})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, data)
	}
	code, data = e.do(agentA, "GET", "/agent/tasks?wait=0", nil)
	if code != http.StatusOK {
		t.Fatalf("poll: %d", code)
	}
	var task api.Task
	json.Unmarshal(data, &task)
	if code, _ := e.do(agentB, "POST", "/agent/tasks/"+task.ID+"/result", api.TaskResult{OK: true}); code != http.StatusNotFound {
		t.Fatalf("foreign result: %d", code)
	}
	if code, _ := e.do(agentA, "POST", "/agent/tasks/"+task.ID+"/result", api.TaskResult{OK: true}); code != http.StatusNoContent {
		t.Fatalf("own result: %d", code)
	}
}

func TestTaskValidationAtServer(t *testing.T) {
	e := setup(t)
	id, _ := e.enroll()
	code, _ := e.do(e.login("admin"), "POST", "/api/devices/"+id+"/tasks",
		map[string]any{"type": "shell.exec", "payload": map[string]string{"cmd": "id"}})
	if code != http.StatusBadRequest {
		t.Fatalf("got %d", code)
	}
}

func TestRequestApprovalFlow(t *testing.T) {
	e := setup(t)
	id, agent := e.enroll()
	member, admin := e.login("anna"), e.login("admin")

	code, data := e.do(member, "POST", "/api/requests", map[string]string{"device_id": id, "kind": "sudo", "detail": "30", "reason": "Treiber"})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, data)
	}
	var created struct{ ID string }
	json.Unmarshal(data, &created)

	if code, _ := e.do(agent, "GET", "/agent/tasks?wait=0", nil); code != http.StatusNoContent {
		t.Fatalf("task exists before approval: %d", code)
	}
	if code, _ := e.do(admin, "POST", "/api/requests/"+created.ID+"/approve", nil); code != http.StatusNoContent {
		t.Fatalf("approve: %d", code)
	}
	if code, _ := e.do(admin, "POST", "/api/requests/"+created.ID+"/approve", nil); code != http.StatusConflict {
		t.Fatalf("double approve: %d", code)
	}
	code, data = e.do(agent, "GET", "/agent/tasks?wait=0", nil)
	if code != http.StatusOK {
		t.Fatalf("poll: %d", code)
	}
	var task api.Task
	json.Unmarshal(data, &task)
	if task.Type != api.TaskSudoGrant || !strings.Contains(string(task.Payload), `"user":"anna"`) {
		t.Fatalf("wrong task: %+v", task)
	}
	if code, _ := e.do(agent, "GET", "/agent/tasks?wait=0", nil); code != http.StatusNoContent {
		t.Fatalf("double approval created a second task: %d", code)
	}
}

func TestMemberRequestsAreInvalidatedAndPrivate(t *testing.T) {
	e := setup(t)
	id, _ := e.enroll()
	anna := e.login("anna")
	if code, _ := e.do(anna, "POST", "/api/requests", map[string]string{"device_id": id, "kind": "software", "detail": "--evil"}); code != http.StatusBadRequest {
		t.Fatalf("bad package: %d", code)
	}
	if code, _ := e.do(anna, "POST", "/api/requests", map[string]string{"device_id": id, "kind": "sudo", "detail": "99999"}); code != http.StatusBadRequest {
		t.Fatalf("too long: %d", code)
	}
	if code, _ := e.do(anna, "POST", "/api/requests", map[string]string{"device_id": id, "kind": "software", "detail": "vim"}); code != http.StatusCreated {
		t.Fatalf("valid: %d", code)
	}
	hash, _ := HashPassword(testPassword)
	if _, err := e.store.CreateUser(context.Background(), "ben", "ben", hash, "member"); err != nil {
		t.Fatal(err)
	}
	_, data := e.do(e.login("ben"), "GET", "/api/requests", nil)
	if strings.Contains(string(data), "vim") {
		t.Fatal("member sees another member's request")
	}
}

func TestMemberSeesNoDeviceDetails(t *testing.T) {
	e := setup(t)
	_, agent := e.enroll()
	e.do(agent, "POST", "/agent/report", api.Report{Hostname: "laptop", Kernel: "secret-kernel"})
	_, data := e.do(e.login("anna"), "GET", "/api/devices", nil)
	if strings.Contains(string(data), "secret-kernel") {
		t.Fatal("report leaked to member")
	}
}
