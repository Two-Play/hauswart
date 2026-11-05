// Package server implements the web API, the agent endpoints and the
// request-and-approve workflow.
package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GehirnInc/crypt/sha512_crypt"
	"golang.org/x/crypto/bcrypt"

	"github.com/philippe/hauswart/internal/api"
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

	// dummyHash keeps login timing equal for unknown usernames.
	dummyHash []byte

	// index is the dashboard entry page, nil if the dashboard was not built.
	index []byte
}

type loginFailure struct {
	count int
	until time.Time
}

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
		store:     st,
		ca:        ca,
		publicURL: strings.TrimRight(publicURL, "/"),
		log:       log,
		waiters:   map[string]chan struct{}{},
		failures:  map[string]*loginFailure{},
		dummyHash: dummy,
		index:     index,
	}, nil
}

// TLSConfig accepts browsers without a client certificate and agents with
// one. Agent routes reject requests that carry no verified certificate.
func (s *Server) TLSConfig(hosts []string) (*tls.Config, error) {
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
	mux.HandleFunc("GET /ca.pem", s.handleCA)

	mux.HandleFunc("POST /agent/enroll", s.handleEnroll)
	mux.Handle("POST /agent/report", s.agent(s.handleReport))
	mux.Handle("GET /agent/tasks", s.agent(s.handlePoll))
	mux.Handle("POST /agent/tasks/{id}/result", s.agent(s.handleResult))

	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.Handle("POST /api/logout", s.user(s.handleLogout))
	mux.Handle("GET /api/me", s.user(s.handleMe))
	mux.Handle("POST /api/password", s.user(s.handleChangePassword))
	mux.Handle("GET /api/devices", s.user(s.handleDevices))
	mux.Handle("GET /api/requests", s.user(s.handleListRequests))
	mux.Handle("POST /api/requests", s.user(s.handleCreateRequest))

	mux.Handle("POST /api/requests/{id}/approve", s.admin(s.handleApprove))
	mux.Handle("POST /api/requests/{id}/deny", s.admin(s.handleDeny))
	mux.Handle("POST /api/enroll-tokens", s.admin(s.handleEnrollToken))
	mux.Handle("POST /api/devices/{id}/revoke", s.admin(s.handleRevoke))
	mux.Handle("POST /api/devices/{id}/tasks", s.admin(s.handleCreateTask))
	mux.Handle("POST /api/devices/{id}/start-password", s.admin(s.handleStartPassword))
	mux.Handle("GET /api/tasks", s.admin(s.handleTasks))
	mux.Handle("GET /api/users", s.admin(s.handleUsers))
	mux.Handle("POST /api/users", s.admin(s.handleCreateUser))
	mux.Handle("DELETE /api/users/{id}", s.admin(s.handleDeleteUser))
	mux.Handle("GET /api/audit", s.admin(s.handleAudit))

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

// --- auth wrappers ---

type userHandler func(http.ResponseWriter, *http.Request, store.User)
type deviceHandler func(http.ResponseWriter, *http.Request, string)

func (s *Server) user(next userHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Browsers cannot attach a custom header to a cross-site form post,
		// so this backs up the SameSite cookie against CSRF.
		if r.Method != http.MethodGet && r.Header.Get("X-Hauswart") != "1" {
			fail(w, http.StatusForbidden, "missing X-Hauswart header")
			return
		}
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			fail(w, http.StatusUnauthorized, "not logged in")
			return
		}
		u, err := s.store.SessionUser(r.Context(), c.Value)
		if errors.Is(err, store.ErrNotFound) {
			fail(w, http.StatusUnauthorized, "not logged in")
			return
		}
		if err != nil {
			s.internal(w, err)
			return
		}
		next(w, r, u)
	})
}

func (s *Server) admin(next userHandler) http.Handler {
	return s.user(func(w http.ResponseWriter, r *http.Request, u store.User) {
		if u.Role != "admin" {
			fail(w, http.StatusForbidden, "admin only")
			return
		}
		next(w, r, u)
	})
}

func (s *Server) agent(next deviceHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			fail(w, http.StatusUnauthorized, "client certificate required")
			return
		}
		leaf := r.TLS.VerifiedChains[0][0]
		id := leaf.Subject.CommonName
		ok, err := s.store.DeviceAuthorized(r.Context(), id, leaf.SerialNumber.Text(16))
		if err != nil {
			s.internal(w, err)
			return
		}
		if !ok {
			fail(w, http.StatusForbidden, "device revoked or unknown")
			return
		}
		next(w, r, id)
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

func (s *Server) handleCA(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(s.ca.CertPEM)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	ip := clientIP(r)
	if s.lockedOut(ip) {
		fail(w, http.StatusTooManyRequests, "too many attempts, try again in a minute")
		return
	}
	u, err := s.store.UserByName(r.Context(), in.Username)
	hash := s.dummyHash
	if err == nil {
		hash = []byte(u.PasswordHash())
	} else if !errors.Is(err, store.ErrNotFound) {
		s.internal(w, err)
		return
	}
	cmpErr := bcrypt.CompareHashAndPassword(hash, []byte(in.Password))
	if err != nil || cmpErr != nil {
		s.recordFailure(ip)
		s.audit(r, in.Username, "login.failed", ip)
		fail(w, http.StatusUnauthorized, "wrong username or password")
		return
	}
	s.clearFailures(ip)
	token, err := s.store.CreateSession(r.Context(), u.ID, sessionTTL)
	if err != nil {
		s.internal(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", MaxAge: int(sessionTTL.Seconds()),
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode,
	})
	s.audit(r, u.Username, "login", ip)
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) lockedOut(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.failures[ip]
	if f == nil {
		return false
	}
	if f.count >= maxLoginFails && time.Now().Before(f.until) {
		return true
	}
	if time.Now().After(f.until) {
		delete(s.failures, ip)
	}
	return false
}

func (s *Server) recordFailure(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.failures[ip]
	if f == nil {
		f = &loginFailure{}
		s.failures[ip] = f
	}
	f.count++
	f.until = time.Now().Add(loginLockout)
}

func (s *Server) clearFailures(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.failures, ip)
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var in api.EnrollRequest
	if !readJSON(w, r, &in) {
		return
	}
	ok, err := s.store.ConsumeEnrollToken(r.Context(), in.Token)
	if err != nil {
		s.internal(w, err)
		return
	}
	if !ok {
		fail(w, http.StatusForbidden, "enrollment token invalid or expired")
		return
	}
	id := store.RandomToken()[:32]
	cert, serial, err := s.ca.SignDevice([]byte(in.CSR), id)
	if err != nil {
		fail(w, http.StatusBadRequest, "invalid CSR")
		return
	}
	hostname := in.Hostname
	if len(hostname) > 253 {
		hostname = hostname[:253]
	}
	if err := s.store.CreateDevice(r.Context(), id, hostname, serial); err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, "agent:"+id, "device.enrolled", hostname)
	writeJSON(w, http.StatusOK, api.EnrollResponse{DeviceID: id, Cert: string(cert)})
}

// --- agent ---

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request, id string) {
	var rep api.Report
	if !readJSON(w, r, &rep) {
		return
	}
	if err := s.store.SaveReport(r.Context(), id, rep); err != nil {
		s.internal(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handlePoll is a long poll: it returns a task as soon as one exists, or 204
// when the wait runs out.
func (s *Server) handlePoll(w http.ResponseWriter, r *http.Request, id string) {
	wait := maxPollWait
	if v, err := strconv.Atoi(r.URL.Query().Get("wait")); err == nil && v >= 0 && time.Duration(v)*time.Second < wait {
		wait = time.Duration(v) * time.Second
	}
	if err := s.store.TouchDevice(r.Context(), id); err != nil {
		s.internal(w, err)
		return
	}
	wake := s.waiter(id)
	timeout := time.After(wait)
	for {
		task, err := s.store.ClaimTask(r.Context(), id)
		if err != nil {
			s.internal(w, err)
			return
		}
		if task != nil {
			writeJSON(w, http.StatusOK, task)
			return
		}
		select {
		case <-wake:
		case <-timeout:
			w.WriteHeader(http.StatusNoContent)
			return
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) waiter(id string) chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.waiters[id]
	if !ok {
		ch = make(chan struct{}, 1)
		s.waiters[id] = ch
	}
	return ch
}

func (s *Server) wake(id string) {
	select {
	case s.waiter(id) <- struct{}{}:
	default:
	}
}

func (s *Server) handleResult(w http.ResponseWriter, r *http.Request, id string) {
	var res api.TaskResult
	if !readJSON(w, r, &res) {
		return
	}
	err := s.store.FinishTask(r.Context(), id, r.PathValue("id"), res)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusNotFound, "no such running task")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- session ---

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, _ store.User) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		if err := s.store.DeleteSession(r.Context(), c.Value); err != nil {
			s.internal(w, err)
			return
		}
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(w http.ResponseWriter, _ *http.Request, u store.User) {
	writeJSON(w, http.StatusOK, u)
}

// --- devices and tasks ---

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request, u store.User) {
	devices, err := s.store.ListDevices(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	if u.Role != "admin" {
		// Members only need something to pick from when filing a request.
		for i := range devices {
			devices[i].Report = nil
		}
	}
	writeJSON(w, http.StatusOK, devices)
}

func (s *Server) handleEnrollToken(w http.ResponseWriter, r *http.Request, u store.User) {
	token, err := s.store.CreateEnrollToken(r.Context(), enrollTokenTTL)
	if err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, u.Username, "enroll_token.created", "")
	writeJSON(w, http.StatusCreated, map[string]string{
		"command": fmt.Sprintf("sudo hauswart-agent enroll --server %s --token %s --ca-fingerprint %s",
			s.publicURL, token, s.ca.Fingerprint()),
	})
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request, u store.User) {
	id := r.PathValue("id")
	err := s.store.RevokeDevice(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusNotFound, "no such device")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, u.Username, "device.revoked", id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleCreateTask(w http.ResponseWriter, r *http.Request, u store.User) {
	var in struct {
		Type    string          `json:"type"`
		Payload json.RawMessage `json:"payload"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if len(in.Payload) == 0 {
		in.Payload = json.RawMessage(`{}`)
	}
	if in.Type == api.TaskUserPassword {
		// Only the start-password route may create these, because it keeps
		// the hash out of the audit log.
		fail(w, http.StatusBadRequest, "use the start-password route")
		return
	}
	if err := api.Validate(in.Type, in.Payload); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := s.enqueue(r, r.PathValue("id"), in.Type, in.Payload, u.Username)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

// handleStartPassword creates a random password, sends only its hash to the
// device and returns the password exactly once. It is stored nowhere.
func (s *Server) handleStartPassword(w http.ResponseWriter, r *http.Request, u store.User) {
	var in struct {
		User string `json:"user"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	password := store.RandomToken()[:startPasswordLen]
	hash, err := sha512_crypt.New().Generate([]byte(password), nil)
	if err != nil {
		s.internal(w, err)
		return
	}
	payload, err := json.Marshal(api.PasswordPayload{User: in.User, Hash: hash})
	if err != nil {
		s.internal(w, err)
		return
	}
	if err := api.Validate(api.TaskUserPassword, payload); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	deviceID := r.PathValue("id")
	id, err := s.store.CreateTask(r.Context(), deviceID, api.TaskUserPassword, payload, u.Username)
	if err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, u.Username, "task."+api.TaskUserPassword, deviceID+" "+in.User)
	s.wake(deviceID)
	writeJSON(w, http.StatusCreated, map[string]string{"id": id, "password": password})
}

func (s *Server) enqueue(r *http.Request, deviceID, taskType string, payload []byte, actor string) (string, error) {
	id, err := s.store.CreateTask(r.Context(), deviceID, taskType, payload, actor)
	if err != nil {
		return "", err
	}
	s.audit(r, actor, "task."+taskType, deviceID+" "+string(payload))
	s.wake(deviceID)
	return id, nil
}

func (s *Server) handleTasks(w http.ResponseWriter, r *http.Request, _ store.User) {
	tasks, err := s.store.ListTasks(r.Context(), listLimit)
	if err != nil {
		s.internal(w, err)
		return
	}
	for i := range tasks {
		if tasks[i].Type == api.TaskUserPassword {
			tasks[i].Payload = json.RawMessage(`{}`)
		}
	}
	writeJSON(w, http.StatusOK, tasks)
}

// --- requests ---

func (s *Server) handleListRequests(w http.ResponseWriter, r *http.Request, u store.User) {
	var filter int64
	if u.Role != "admin" {
		filter = u.ID
	}
	requests, err := s.store.ListRequests(r.Context(), filter)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, requests)
}

func (s *Server) handleCreateRequest(w http.ResponseWriter, r *http.Request, u store.User) {
	var in struct {
		DeviceID string `json:"device_id"`
		Kind     string `json:"kind"`
		Detail   string `json:"detail"`
		Reason   string `json:"reason"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	// Validate now, so a bad request fails for the person filing it rather
	// than for the admin approving it.
	if _, _, err := requestTask(in.Kind, in.Detail, u.LinuxUser); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := s.store.CreateRequest(r.Context(), u.ID, in.DeviceID, in.Kind, in.Detail, in.Reason)
	if err != nil {
		fail(w, http.StatusBadRequest, "unknown device")
		return
	}
	s.audit(r, u.Username, "request.created", in.Kind+" "+in.Detail)
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

// requestTask converts a request into the task it causes once approved. A
// sudo grant's expiry counts from this call, so from approval when approving.
func requestTask(kind, detail, linuxUser string) (string, []byte, error) {
	var taskType string
	var payload any
	switch kind {
	case "software", "flatpak":
		taskType = api.TaskPkgInstall
		if kind == "flatpak" {
			taskType = api.TaskFlatpakInstall
		}
		payload = api.PackagesPayload{Packages: strings.Fields(detail)}
	case "sudo":
		minutes, err := strconv.Atoi(strings.TrimSpace(detail))
		if err != nil || minutes < 1 || minutes > maxSudoMinutes {
			return "", nil, fmt.Errorf("duration must be 1 to %d minutes", maxSudoMinutes)
		}
		taskType = api.TaskSudoGrant
		payload = api.SudoGrantPayload{User: linuxUser, ExpiresAt: time.Now().Add(time.Duration(minutes) * time.Minute)}
	default:
		return "", nil, fmt.Errorf("unknown request kind %q", kind)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", nil, err
	}
	if err := api.Validate(taskType, raw); err != nil {
		return "", nil, err
	}
	return taskType, raw, nil
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request, u store.User) {
	req, err := s.store.GetRequest(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusNotFound, "no such request")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	taskType, payload, err := requestTask(req.Kind, req.Detail, req.LinuxUser)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	won, err := s.store.DecideRequest(r.Context(), req.ID, "approved", u.Username)
	if err != nil {
		s.internal(w, err)
		return
	}
	if !won {
		fail(w, http.StatusConflict, "request was already decided")
		return
	}
	if _, err := s.enqueue(r, req.DeviceID, taskType, payload, u.Username); err != nil {
		s.internal(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeny(w http.ResponseWriter, r *http.Request, u store.User) {
	id := r.PathValue("id")
	won, err := s.store.DecideRequest(r.Context(), id, "denied", u.Username)
	if err != nil {
		s.internal(w, err)
		return
	}
	if !won {
		fail(w, http.StatusConflict, "request not open")
		return
	}
	s.audit(r, u.Username, "request.denied", id)
	w.WriteHeader(http.StatusNoContent)
}

// --- users and audit ---

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request, _ store.User) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request, u store.User) {
	var in struct {
		Username  string `json:"username"`
		LinuxUser string `json:"linux_user"`
		Password  string `json:"password"`
		Role      string `json:"role"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.LinuxUser == "" {
		in.LinuxUser = in.Username
	}
	if !api.ValidUser(in.Username) || !api.ValidUser(in.LinuxUser) {
		fail(w, http.StatusBadRequest, "invalid username")
		return
	}
	if in.Role != "admin" && in.Role != "member" {
		fail(w, http.StatusBadRequest, "role must be admin or member")
		return
	}
	if len(in.Password) < minPasswordLen {
		fail(w, http.StatusBadRequest, fmt.Sprintf("password needs at least %d characters", minPasswordLen))
		return
	}
	hash, err := HashPassword(in.Password)
	if err != nil {
		fail(w, http.StatusBadRequest, "password too long")
		return
	}
	if _, err := s.store.CreateUser(r.Context(), in.Username, in.LinuxUser, hash, in.Role); err != nil {
		fail(w, http.StatusConflict, "username already exists")
		return
	}
	s.audit(r, u.Username, "user.created", in.Username+" ("+in.Role+")")
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request, u store.User) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, "invalid user id")
		return
	}
	switch err := s.store.DeleteUser(r.Context(), id); {
	case errors.Is(err, store.ErrNotFound):
		fail(w, http.StatusNotFound, "no such user")
	case errors.Is(err, store.ErrLastAdmin):
		fail(w, http.StatusConflict, "the last admin cannot be removed")
	case err != nil:
		s.internal(w, err)
	default:
		s.audit(r, u.Username, "user.deleted", r.PathValue("id"))
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, u store.User) {
	var in struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	ip := clientIP(r)
	if s.lockedOut(ip) {
		fail(w, http.StatusTooManyRequests, "too many attempts, try again in a minute")
		return
	}
	current, err := s.store.UserPasswordHash(r.Context(), u.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(current), []byte(in.Current)) != nil {
		s.recordFailure(ip)
		s.audit(r, u.Username, "password.change_failed", ip)
		fail(w, http.StatusForbidden, "current password is wrong")
		return
	}
	if len(in.New) < minPasswordLen {
		fail(w, http.StatusBadRequest, fmt.Sprintf("password needs at least %d characters", minPasswordLen))
		return
	}
	hash, err := HashPassword(in.New)
	if err != nil {
		fail(w, http.StatusBadRequest, "password too long")
		return
	}
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		s.internal(w, err)
		return
	}
	if err := s.store.ChangePassword(r.Context(), u.ID, hash, cookie.Value); err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, u.Username, "password.changed", ip)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, _ store.User) {
	entries, err := s.store.ListAudit(r.Context(), listLimit)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

// HashPassword is exported for the first-start admin bootstrap.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

// --- helpers ---

func (s *Server) audit(r *http.Request, actor, action, detail string) {
	if err := s.store.Audit(r.Context(), actor, action, detail); err != nil {
		s.log.Error("audit write failed", "err", err, "action", action)
	}
}

func (s *Server) internal(w http.ResponseWriter, err error) {
	s.log.Error("request failed", "err", err)
	fail(w, http.StatusInternalServerError, "internal error")
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		fail(w, http.StatusBadRequest, "invalid JSON")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
