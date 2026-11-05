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

	"github.com/philippe/hauswart/internal/api"
	"github.com/philippe/hauswart/internal/notify"
	"github.com/philippe/hauswart/internal/pki"
	"github.com/philippe/hauswart/internal/store"
	"github.com/philippe/hauswart/web"
)

const (
	noncePlaceholder = "__CSP_NONCE__"
	sessionCookie    = "hauswart_session"
	sessionTTL       = 12 * time.Hour
	enrollTokenTTL   = time.Hour
	maxBody          = 2 << 20
	maxPollWait      = 30 * time.Second
	staleTaskAfter   = 45 * time.Minute
	startPasswordLen = 20
	minPasswordLen   = 10
	maxLoginFails    = 5
	loginLockout     = time.Minute
	maxSudoMinutes   = int(api.MaxGrant / time.Minute)
	listLimit        = 200
	janitorInterval  = 5 * time.Minute
)

type Server struct {
	store     *store.Store
	ca        *pki.CA
	publicURL string
	log       *slog.Logger

	mu       sync.Mutex
	waiters  map[string]chan struct{}
	failures map[string]*loginFailure
	// registrations holds the open passkey registration of each user.
	registrations map[int64]registration

	// dummyHash keeps login timing equal for unknown usernames.
	dummyHash []byte

	// index is the dashboard entry page, nil if the dashboard was not built.
	index []byte

	// notifier tells admins about new requests, nil if nothing is configured.
	notifier *notify.Notifier
	// ownHosts are the names of this server, which no service may get.
	ownHosts []string
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

	return securityHeaders(http.MaxBytesHandler(mux, maxBody))
}

// Janitor expires stale state until ctx ends.
func (s *Server) Janitor(ctx context.Context) {
	ticker := time.NewTicker(janitorInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.store.Cleanup(ctx, staleTaskAfter); err != nil {
				s.log.Error("cleanup failed", "err", err)
			}
		}
	}
}

const cspBase = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

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
