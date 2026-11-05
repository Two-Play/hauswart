package notify

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func writeEnv(t *testing.T, mode os.FileMode, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "notify.env")
	if err := os.WriteFile(path, []byte(text), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestMissingFileMeansOff(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "missing"))
	if err != nil || cfg.Enabled() {
		t.Fatalf("%+v, %v", cfg, err)
	}
}

func TestCommentsOnlyMeansOff(t *testing.T) {
	cfg, err := Load(writeEnv(t, 0o600, "# NTFY_URL=https://example\n\n"))
	if err != nil || cfg.Enabled() {
		t.Fatalf("%+v, %v", cfg, err)
	}
}

func TestLoadRefusesOpenPermissions(t *testing.T) {
	for _, mode := range []os.FileMode{0o640, 0o644, 0o604, 0o660} {
		if _, err := Load(writeEnv(t, mode, "NTFY_URL=https://ntfy.example/topic\n")); err == nil {
			t.Errorf("%o accepted", mode)
		}
	}
}

func TestLoadKeepsSecretsOutOfErrors(t *testing.T) {
	_, err := Load(writeEnv(t, 0o600, "SMTP_PASSWROD=hunter2\n"))
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("got %v", err)
	}
	_, err = Load(writeEnv(t, 0o600, "hunter2\n"))
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("got %v", err)
	}
}

func TestLoadReadsEverything(t *testing.T) {
	cfg, err := Load(writeEnv(t, 0o600, `# comment
NTFY_URL=https://ntfy.example/secret-topic
NTFY_TOKEN="tk_abc=def"
SMTP_HOST=mail.example
SMTP_USER=hauswart
SMTP_PASSWORD='p=ss#word'
SMTP_FROM=Hauswart <hauswart@example.org>
SMTP_TO=a@example.org, b@example.org
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NtfyToken != "tk_abc=def" || cfg.SMTPPassword != "p=ss#word" || cfg.SMTPPort != "587" || cfg.SMTPTLS != "starttls" {
		t.Fatalf("%+v", cfg)
	}
	if len(cfg.SMTPTo) != 2 || cfg.SMTPTo[1] != "b@example.org" {
		t.Fatalf("%+v", cfg.SMTPTo)
	}
	if got := strings.Join(cfg.Channels(), " "); got != "ntfy email" {
		t.Fatalf("got %q", got)
	}
}

func TestLoadRefusesClearTextCredentials(t *testing.T) {
	for name, text := range map[string]string{
		"ntfy token over http": "NTFY_URL=http://ntfy.example/t\nNTFY_TOKEN=x\n",
		"password without tls": "SMTP_HOST=mail.example\nSMTP_TLS=none\nSMTP_PASSWORD=x\nSMTP_FROM=a@b.c\nSMTP_TO=a@b.c\n",
		"unknown tls mode":     "SMTP_HOST=mail.example\nSMTP_TLS=maybe\nSMTP_FROM=a@b.c\nSMTP_TO=a@b.c\n",
		"no recipient":         "SMTP_HOST=mail.example\nSMTP_FROM=a@b.c\n",
		"no sender":            "SMTP_HOST=mail.example\nSMTP_TO=a@b.c\n",
		"no scheme":            "NTFY_URL=ntfy.example/t\n",
	} {
		if _, err := Load(writeEnv(t, 0o600, text)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Load(writeEnv(t, 0o600, "NTFY_URL=http://127.0.0.1:1/t\nNTFY_TOKEN=x\n")); err != nil {
		t.Errorf("loopback: %v", err)
	}
}

func run(t *testing.T, n *Notifier) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go n.Run(ctx)
}

func TestNtfyGetsMessageAndToken(t *testing.T) {
	got := make(chan *http.Request, 1)
	bodies := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies <- string(body)
		got <- r
	}))
	defer server.Close()
	n := New(Config{NtfyURL: server.URL + "/topic", NtfyToken: "tk"}, x509.NewCertPool(), quiet())
	run(t, n)
	n.Send("hello")
	if body := <-bodies; body != "hello" {
		t.Fatalf("got %q", body)
	}
	r := <-got
	if r.URL.Path != "/topic" || r.Header.Get("Authorization") != "Bearer tk" || r.Header.Get("Title") != "Hauswart" {
		t.Fatalf("%v %v", r.URL, r.Header)
	}
}

func TestSendNeverWaitsForADeadServer(t *testing.T) {
	block := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-block }))
	defer server.Close()
	defer close(block)
	n := New(Config{NtfyURL: server.URL}, x509.NewCertPool(), quiet())
	run(t, n)
	start := time.Now()
	for range maxPerHour + 10 {
		n.Send("hello")
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("Send blocked for %v", took)
	}
}

func TestDeliveryIsRetried(t *testing.T) {
	old := retryDelay
	retryDelay = time.Millisecond
	t.Cleanup(func() { retryDelay = old })
	var mu sync.Mutex
	attempts := 0
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		attempts++
		if attempts < sendAttempts {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		close(done)
	}))
	defer server.Close()
	n := New(Config{NtfyURL: server.URL}, x509.NewCertPool(), quiet())
	run(t, n)
	n.Send("hello")
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("no successful attempt")
	}
}

func TestTokenDoesNotFollowRedirects(t *testing.T) {
	leaked := make(chan string, 1)
	other := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		leaked <- r.Header.Get("Authorization")
	}))
	defer other.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	n := New(Config{NtfyURL: server.URL, NtfyToken: "tk"}, x509.NewCertPool(), quiet())
	if err := n.sendNtfy(context.Background(), "x"); err == nil {
		t.Fatal("a redirect counted as delivered")
	}
	select {
	case got := <-leaked:
		t.Fatalf("followed the redirect with %q", got)
	default:
	}
}

func TestRateLimit(t *testing.T) {
	n := New(Config{}, x509.NewCertPool(), quiet())
	now := time.Now()
	for i := range maxPerHour {
		if !n.allow(now) {
			t.Fatalf("refused number %d", i)
		}
	}
	if n.allow(now) {
		t.Fatal("no limit")
	}
	if !n.allow(now.Add(time.Hour)) {
		t.Fatal("the limit never ends")
	}
}

func TestLogsHideTheTopic(t *testing.T) {
	var logs bytes.Buffer
	n := New(Config{NtfyURL: "http://127.0.0.1:1/secret-topic"}, x509.NewCertPool(), slog.New(slog.NewTextHandler(&logs, nil)))
	old := retryDelay
	retryDelay = time.Millisecond
	t.Cleanup(func() { retryDelay = old })
	n.deliver(context.Background(), "ntfy", func(ctx context.Context) error { return n.sendNtfy(ctx, "x") })
	if logs.Len() == 0 || strings.Contains(logs.String(), "secret-topic") {
		t.Fatalf("got %q", logs.String())
	}
}

// fakeSMTP answers just enough of the protocol, and records what it receives.
type fakeSMTP struct {
	listener net.Listener
	startTLS bool
	mu       sync.Mutex
	lines    []string
}

func newFakeSMTP(t *testing.T, startTLS bool) *fakeSMTP {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	f := &fakeSMTP{listener: listener, startTLS: startTLS}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
	return f
}

func (f *fakeSMTP) serve(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	io.WriteString(conn, "220 test\r\n")
	data := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		f.mu.Lock()
		f.lines = append(f.lines, strings.TrimRight(line, "\r\n"))
		f.mu.Unlock()
		command := strings.ToUpper(strings.Fields(line + " x")[0])
		switch {
		case data:
			if strings.TrimRight(line, "\r\n") == "." {
				data = false
				io.WriteString(conn, "250 ok\r\n")
			}
		case command == "EHLO":
			if f.startTLS {
				io.WriteString(conn, "250-test\r\n250 STARTTLS\r\n")
			} else {
				io.WriteString(conn, "250 test\r\n")
			}
		case command == "DATA":
			data = true
			io.WriteString(conn, "354 go\r\n")
		case command == "QUIT":
			io.WriteString(conn, "221 bye\r\n")
			return
		default:
			io.WriteString(conn, "250 ok\r\n")
		}
	}
}

func (f *fakeSMTP) text() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.lines, "\n")
}

func (f *fakeSMTP) config(mode string) Config {
	host, port, _ := net.SplitHostPort(f.listener.Addr().String())
	return Config{SMTPHost: host, SMTPPort: port, SMTPTLS: mode, SMTPFrom: "Hauswart <from@example.org>", SMTPTo: []string{"to@example.org"}}
}

func TestMailIsPlainAndFixed(t *testing.T) {
	f := newFakeSMTP(t, false)
	n := New(f.config(tlsNone), x509.NewCertPool(), quiet())
	if err := n.sendMail(context.Background(), "Anna asks for sudo on küche.\nDecide: https://x"); err != nil {
		t.Fatal(err)
	}
	text := f.text()
	for _, want := range []string{"MAIL FROM:<from@example.org>", "RCPT TO:<to@example.org>", "Subject: New request in Hauswart", "Anna asks for sudo on küche.", "charset=utf-8"} {
		if !strings.Contains(text, want) {
			t.Errorf("no %q in %s", want, text)
		}
	}
}

func TestMailRefusesAServerWithoutStartTLS(t *testing.T) {
	f := newFakeSMTP(t, false)
	cfg := f.config(tlsStart)
	cfg.SMTPUser, cfg.SMTPPassword = "user", "hunter2"
	n := New(cfg, x509.NewCertPool(), quiet())
	err := n.sendMail(context.Background(), "hello")
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("got %v", err)
	}
	if text := f.text(); strings.Contains(text, "AUTH") || strings.Contains(text, "hello") {
		t.Fatalf("went on without TLS: %s", text)
	}
}

func TestMailChecksTheCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	host, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	n := New(Config{SMTPHost: host, SMTPPort: port, SMTPTLS: tlsImplicit, SMTPFrom: "a@b.c", SMTPTo: []string{"a@b.c"}}, x509.NewCertPool(), quiet())
	err := n.sendMail(context.Background(), "hello")
	var unknown x509.UnknownAuthorityError
	var verification *tls.CertificateVerificationError
	if !errors.As(err, &unknown) && !errors.As(err, &verification) {
		t.Fatalf("got %v", err)
	}
}
