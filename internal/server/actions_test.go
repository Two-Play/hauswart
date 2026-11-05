package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/philippe/hauswart/internal/api"
	"github.com/philippe/hauswart/internal/pki"
	"github.com/philippe/hauswart/internal/store"
)

// scopedServer serves a CA limited to home.lan, unlike the one from setup.
func scopedServer(t *testing.T) (*httptest.Server, *Server, *http.Cookie, string) {
	t.Helper()
	dir := t.TempDir()
	ca, err := pki.LoadOrCreate(filepath.Join(dir, "pki"), "home.lan", "10.8.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv, err := New(st, ca, "https://hauswart.home.lan", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	srv.ownHosts = []string{"hauswart.home.lan", "10.8.0.1"}
	if _, err := st.CreateUser(context.Background(), "root-admin", "", "x", "admin"); err != nil {
		t.Fatal(err)
	}
	user, err := st.UserByName(context.Background(), "root-admin")
	if err != nil {
		t.Fatal(err)
	}
	token, err := st.CreateSession(context.Background(), user.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, srv, &http.Cookie{Name: sessionCookie, Value: token}, dir
}

func call(t *testing.T, ts *httptest.Server, cookie *http.Cookie, method, path, body string) (*http.Response, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Hauswart", "1")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	json.Unmarshal(raw, &out)
	return resp, out
}

func TestIssueServiceCertificate(t *testing.T) {
	ts, srv, cookie, dir := scopedServer(t)
	resp, out := call(t, ts, cookie, "POST", "/api/certificates", `{"names":["NAS.home.lan","10.8.0.5","nas.home.lan"],"days":30}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("%d %v", resp.StatusCode, out)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache: %q", got)
	}
	key, _ := out["key"].(string)
	if !strings.Contains(key, "PRIVATE KEY") {
		t.Fatalf("no key: %v", out)
	}
	leaf, err := pki.ParseCert([]byte(out["cert"].(string)))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(leaf.DNSNames, " "); got != "nas.home.lan" {
		t.Fatalf("names: %q", got)
	}

	certs, err := srv.store.ListServiceCerts(context.Background())
	if err != nil || len(certs) != 1 {
		t.Fatalf("%v, %v", certs, err)
	}
	if certs[0].NotAfter != leaf.NotAfter.Unix() || certs[0].CreatedBy != "root-admin" {
		t.Fatalf("%+v", certs[0])
	}
	entries, err := srv.store.ListAudit(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	logged, _ := json.Marshal(entries)
	if !strings.Contains(string(logged), "certificate.issued") || !strings.Contains(string(logged), "nas.home.lan") {
		t.Fatalf("audit: %s", logged)
	}

	// The key is handed out and kept nowhere: not in the list, the audit log
	// or anything on disk. The body of the PEM is the part that counts.
	body := strings.Split(key, "\n")[1]
	listed, _ := json.Marshal(certs)
	if strings.Contains(string(listed), body) || strings.Contains(string(logged), body) {
		t.Fatal("key in the list or the audit log")
	}
	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err == nil && strings.Contains(string(raw), body) {
			t.Errorf("key in %s", path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestServiceCertificateRefusals(t *testing.T) {
	ts, srv, cookie, _ := scopedServer(t)
	for body, code := range map[string]string{
		`{"names":["google.com"]}`:              api.ErrCertOutsideCA,
		`{"names":["nas.home.lan","evil.com"]}`: api.ErrCertOutsideCA,
		`{"names":["192.168.1.1"]}`:             api.ErrCertOutsideCA,
		`{"names":["*.home.lan"]}`:              api.ErrInvalidCertName,
		`{"names":["nas home.lan"]}`:            api.ErrInvalidCertName,
		`{"names":[]}`:                          api.ErrNoCertNames,
		`{"names":["nas.home.lan"],"days":398}`: api.ErrInvalidCertDays,
		`{"names":["nas.home.lan"],"days":-1}`:  api.ErrInvalidCertDays,
		`{"names":["hauswart.home.lan"]}`:       api.ErrCertServerName,
		`{"names":["nas.home.lan","10.8.0.1"]}`: api.ErrCertServerName,
	} {
		resp, out := call(t, ts, cookie, "POST", "/api/certificates", body)
		if resp.StatusCode != http.StatusBadRequest || out["code"] != code {
			t.Errorf("%s: %d %v", body, resp.StatusCode, out)
		}
	}
	certs, _ := srv.store.ListServiceCerts(context.Background())
	if len(certs) != 0 {
		t.Fatalf("issued %v", certs)
	}
}

func TestServiceCertificatesAreForAdmins(t *testing.T) {
	ts, _, _, _ := scopedServer(t)
	for _, method := range []string{"GET", "POST"} {
		if resp, _ := call(t, ts, nil, method, "/api/certificates", `{"names":["nas.home.lan"]}`); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: %d", method, resp.StatusCode)
		}
	}
}

func TestUnconstrainedCAIsRefused(t *testing.T) {
	e := setup(t)
	code, out := e.do(e.login("admin"), "POST", "/api/certificates", map[string]any{"names": []string{"nas.home.lan"}})
	if code != http.StatusConflict || !strings.Contains(string(out), api.ErrCANotConstrained) {
		t.Fatalf("%d %s", code, out)
	}
}

func TestNewRequestNotifiesAdminsWithoutItsDetails(t *testing.T) {
	bodies := make(chan string, 1)
	ntfy := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies <- string(body)
	}))
	defer ntfy.Close()
	path := filepath.Join(t.TempDir(), "notify.env")
	if err := os.WriteFile(path, []byte("NTFY_URL="+ntfy.URL+"/topic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ts, srv, _, _ := scopedServer(t)
	srv.StartNotifications(ctx, path)
	st := srv.store
	id, err := st.CreateUser(ctx, "anna", "anna", "x", "member")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateDevice(ctx, "d1", "evil\nhost http://phish.example", "s1"); err != nil {
		t.Fatal(err)
	}
	token, err := st.CreateSession(ctx, id, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetUserDevices(ctx, id, []string{"d1"}); err != nil {
		t.Fatal(err)
	}
	resp, out := call(t, ts, &http.Cookie{Name: sessionCookie, Value: token}, "POST", "/api/requests",
		`{"device_id":"d1","kind":"software","detail":"secretpkg","reason":"my password is hunter2"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("%d %v", resp.StatusCode, out)
	}
	select {
	case body := <-bodies:
		for _, leak := range []string{"secretpkg", "hunter2", "http://phish.example"} {
			if strings.Contains(body, leak) {
				t.Errorf("%q in %q", leak, body)
			}
		}
		if !strings.Contains(body, "anna asks for software on") || !strings.Contains(body, "https://hauswart.home.lan") {
			t.Errorf("got %q", body)
		}
		if lines := strings.Count(body, "\n"); lines != 1 {
			t.Errorf("hostname added lines: %q", body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no notification")
	}
}

func TestBadNotifyFileLeavesTheServerRunning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify.env")
	if err := os.WriteFile(path, []byte("NTFY_URL=https://ntfy.example/t\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, srv, _, _ := scopedServer(t)
	srv.StartNotifications(context.Background(), path)
	if srv.notifier != nil {
		t.Fatal("used a file others can read")
	}
}
