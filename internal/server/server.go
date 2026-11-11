// Package server implements the web API, the agent endpoints and the
// request-and-approve workflow.
package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/catalog"
	"github.com/Two-Play/hauswart/internal/notify"
	"github.com/Two-Play/hauswart/internal/pki"
	"github.com/Two-Play/hauswart/internal/store"
	"github.com/Two-Play/hauswart/web"
)

const (
	noncePlaceholder = "__CSP_NONCE__"
	sessionCookie    = "hauswart_session"
	sessionTTL       = 12 * time.Hour
	enrollTokenTTL   = time.Hour
	maxBody          = 2 << 20
	maxPollWait      = 30 * time.Second
	// requestHistory is how far back a device learns about its requests.
	requestHistory   = 30 * 24 * time.Hour
	staleTaskAfter   = 45 * time.Minute
	startPasswordLen = 20
	minPasswordLen   = 10
	maxLoginFails    = 5
	loginLockout     = time.Minute
	maxSudoMinutes   = int(api.MaxGrant / time.Minute)
	listLimit        = 200
	janitorInterval  = 5 * time.Minute
)

// sender is what the server needs of a notifier, which tests replace.
type sender interface {
	Send(message string)
	SendAs(subject notify.Subject, message string)
}

type Server struct {
	store     *store.Store
	ca        *pki.CA
	publicURL string
	log       *slog.Logger

	// policyMu keeps policy changes for a device one after the other.
	policyMu sync.Mutex
	// passkeyTypesMu does the same for the passkey types.
	passkeyTypesMu sync.Mutex

	mu       sync.Mutex
	waiters  map[string]chan struct{}
	failures map[string]*loginFailure
	// registrations holds the open passkey registration of each user.
	registrations map[int64]registration

	// dummyHash keeps login timing equal for unknown usernames.
	dummyHash []byte

	// index is the dashboard entry page, nil if the dashboard was not built.
	index []byte

	// notifier tells admins about new requests, failures and deviations, nil if
	// nothing is configured.
	notifier sender
	// ownHosts are the names of this server, which no service may get.
	ownHosts []string
	// oidc logs people in through the identity provider, nil if not configured.
	oidc *oidcLogin
	// flathub answers Flatpak searches, nil if they stay on the server.
	flathub *catalog.Flathub
	// terminals are the live shells that are open or about to be.
	terminals terminalHub
	// exposure is what makes the server look reachable from the internet.
	exposure exposureWatch
	// tpm holds the steps of attestation that wait for a device.
	tpm tpmState
}

type loginFailure struct {
	count int
	until time.Time
}

// routeGroups collects the routes of every feature. A feature lives in its own
// file and adds its routes from an init function.
var routeGroups []func(*Server, *http.ServeMux)

func addRoutes(add func(*Server, *http.ServeMux)) { routeGroups = append(routeGroups, add) }

func New(st *store.Store, ca *pki.CA, publicURL string, log *slog.Logger) (*Server, error) {
	dummy, err := bcrypt.GenerateFromPassword([]byte(store.RandomToken()[:32]), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	index, err := fs.ReadFile(web.FS, "index.html")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return &Server{
		store:         st,
		ca:            ca,
		publicURL:     strings.TrimRight(publicURL, "/"),
		log:           log,
		waiters:       map[string]chan struct{}{},
		failures:      map[string]*loginFailure{},
		registrations: map[int64]registration{},
		terminals:     terminalHub{sessions: map[string]*terminalSession{}},
		dummyHash:     dummy,
		index:         index,
	}, nil
}

// TLSConfig accepts browsers without a client certificate and agents with
// one. Agent routes reject requests that carry no verified certificate.
func (s *Server) TLSConfig(hosts []string) (*tls.Config, error) {
	s.ownHosts = hosts
	cert, err := s.ca.ServerCert(hosts)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    s.ca.Pool(),
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("GET /", http.FileServerFS(web.FS))
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	for _, add := range routeGroups {
		add(s, mux)
	}

	limited := securityHeaders(http.MaxBytesHandler(mux, maxBody))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.seen(r)
		limited.ServeHTTP(w, r)
	})
}

// Janitor expires stale state until ctx ends.
func (s *Server) Janitor(ctx context.Context) {
	ticker := time.NewTicker(janitorInterval)
	defer ticker.Stop()
	// A restart should not leave accounts out of date for a whole interval.
	s.syncDirectory(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.store.Cleanup(ctx, staleTaskAfter); err != nil {
				s.log.Error("cleanup failed", "err", err)
			}
			s.lapseWaiting(ctx, time.Now())
			s.syncDirectory(ctx)
		}
	}
}

// lapseWaiting closes what waited too long for approval, and says so in the
// audit log.
func (s *Server) lapseWaiting(ctx context.Context, now time.Time) {
	lapsed, err := s.store.LapseWaiting(ctx, now)
	if err != nil {
		s.log.Error("lapsing waiting tasks failed", "err", err)
	}
	for _, t := range lapsed {
		s.terminals.endTask(t.ID, "nobody approved it in time")
		if err := s.store.Audit(ctx, "server", "task.lapsed", t.Type+" "+t.ID+" on "+t.DeviceID); err != nil {
			s.log.Error("audit failed", "err", err)
		}
	}
}

// img-src allows data: for the preview of a picture someone chose themselves.
const cspBase = "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", cspBase)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// --- public ---

// handleIndex serves the dashboard with a nonce that is new on every request.
// Mantine injects style tags at runtime; the nonce lets exactly those through
// without allowing inline styles in general.
func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	if s.index == nil {
		http.Error(w, "dashboard not built, run make build", http.StatusServiceUnavailable)
		return
	}
	nonce := store.RandomToken()[:32]
	w.Header().Set("Content-Security-Policy", fmt.Sprintf("%s; style-src 'self' 'nonce-%s'", cspBase, nonce))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(bytes.ReplaceAll(s.index, []byte(noncePlaceholder), []byte(nonce)))
}
