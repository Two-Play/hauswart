package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/store"
)

const (
	// terminalFrame caps a single message in either direction.
	terminalFrame = 32 << 10
	// terminalAway is how long a session runs on without anyone watching it,
	// so that the admin can come back to it after closing the window.
	terminalAway = 10 * time.Minute
	// terminalReplay is what a browser that connects again sees of the output
	// it missed.
	terminalReplay = 64 << 10
)

func init() {
	addRoutes(func(s *Server, mux *http.ServeMux) {
		mux.Handle("POST /api/devices/{id}/terminal", s.admin(s.handleTerminalCreate))
		mux.Handle("GET /api/terminal/{session}", s.admin(s.handleBrowserTerminal))
		mux.Handle("GET /api/terminals", s.admin(s.handleTerminals))
		mux.Handle("GET /agent/terminal/{session}", s.agent(s.handleAgentTerminal))
	})
}

// terminalSession is one live shell. The device and a browser each connect to
// it, and the server passes on what one sends to the other. It sees everything
// that goes through, and keeps nothing of it beyond the replay buffer.
type terminalSession struct {
	id, task, device, hostname, admin, user string
	minutes                                 int

	mu      sync.Mutex
	agent   *websocket.Conn
	browser *websocket.Conn
	started time.Time
	// ready is closed once the device has connected.
	ready chan struct{}
	// done is closed once the session is over.
	done   chan struct{}
	reason string
	// away ends the session when no browser comes back in time.
	away   *time.Timer
	replay []byte
	// watched says that a browser was connected once, so the next is a return.
	watched bool
}

type terminalHub struct {
	mu       sync.Mutex
	sessions map[string]*terminalSession
}

func (h *terminalHub) get(id string) *terminalSession {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sessions[id]
}

// running lists the sessions of an admin that a device has connected to and
// that have not ended.
func (h *terminalHub) running(admin string) []*terminalSession {
	h.mu.Lock()
	defer h.mu.Unlock()
	var list []*terminalSession
	for _, t := range h.sessions {
		t.mu.Lock()
		live := t.admin == admin && t.agent != nil && !t.closed()
		t.mu.Unlock()
		if live {
			list = append(list, t)
		}
	}
	return list
}

func (h *terminalHub) remove(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.sessions, id)
}

// endTask ends the session of a task that failed or was rejected, so that the
// browser waiting for it hears why instead of waiting on.
func (h *terminalHub) endTask(task, reason string) {
	h.mu.Lock()
	var found *terminalSession
	for id, t := range h.sessions {
		if t.task == task {
			found = t
			delete(h.sessions, id)
		}
	}
	h.mu.Unlock()
	if found != nil {
		found.end(closeText(reason))
	}
}

// closeText fits a reason into a close frame, which holds 123 bytes.
func closeText(reason string) string {
	reason = strings.Join(strings.Fields(reason), " ")
	for len(reason) > 120 {
		_, size := utf8.DecodeLastRuneInString(reason)
		reason = reason[:len(reason)-size]
	}
	return reason
}

func newTerminalSession() string {
	raw := make([]byte, api.TerminalSessionBytes)
	rand.Read(raw)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// handleTerminalCreate queues the task that opens a session. Only a protected
// device can have one: a shell as root needs an approval the device checks.
func (s *Server) handleTerminalCreate(w http.ResponseWriter, r *http.Request, u store.User) {
	var in struct {
		User    string `json:"user"`
		Minutes int    `json:"minutes"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.Minutes == 0 {
		in.Minutes = api.DefaultTerminalMinutes
	}
	deviceID := r.PathValue("id")
	protected, err := s.store.DeviceProtected(r.Context(), deviceID)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusNotFound, api.ErrNoSuchDevice)
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	if !protected {
		fail(w, http.StatusConflict, api.ErrTerminalUnprotected)
		return
	}
	session := newTerminalSession()
	payload, err := json.Marshal(api.TerminalPayload{Session: session, User: in.User, Minutes: in.Minutes})
	if err != nil {
		s.internal(w, err)
		return
	}
	if err := api.Validate(api.TaskTerminalOpen, payload); err != nil {
		failErr(w, http.StatusBadRequest, err)
		return
	}
	hostname := deviceID
	if report, err := s.store.DeviceReport(r.Context(), deviceID); err == nil && report != nil && report.Hostname != "" {
		hostname = report.Hostname
	}
	id, err := s.enqueue(r, deviceID, api.TaskTerminalOpen, payload, u.Username)
	if err != nil {
		s.internal(w, err)
		return
	}
	t := &terminalSession{
		id: session, task: id, device: deviceID, hostname: hostname, admin: u.Username, user: in.User,
		minutes: in.Minutes, ready: make(chan struct{}), done: make(chan struct{}),
	}
	s.terminals.mu.Lock()
	s.terminals.sessions[session] = t
	s.terminals.mu.Unlock()
	// A session the device never opens is forgotten once its approval is too old.
	time.AfterFunc(api.MaxTerminalApproval+time.Minute, func() {
		t.mu.Lock()
		unused := t.agent == nil
		t.mu.Unlock()
		if unused {
			t.end("not started")
			s.terminals.remove(session)
		}
	})
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "session": session})
}

// accept takes over the connection for good. The timeouts of the server are
// for ordinary requests and would end a session after a minute.
func accept(w http.ResponseWriter, r *http.Request) (*websocket.Conn, error) {
	rc := http.NewResponseController(w)
	rc.SetReadDeadline(time.Time{})
	rc.SetWriteDeadline(time.Time{})
	// The default checks that Origin, if any, is this server, so another
	// page cannot open a session with the cookie of an admin.
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return nil, err
	}
	conn.SetReadLimit(terminalFrame)
	return conn, nil
}

// handleAgentTerminal is the device's side. It runs until the session ends.
func (s *Server) handleAgentTerminal(w http.ResponseWriter, r *http.Request, device string) {
	t := s.terminals.get(r.PathValue("session"))
	if t == nil || t.device != device {
		fail(w, http.StatusNotFound, api.ErrTerminalGone)
		return
	}
	// The device connects only for a task it admitted, which it holds then.
	task, err := s.store.GetTask(r.Context(), t.task)
	if err != nil || task.Status != "running" {
		fail(w, http.StatusConflict, api.ErrTerminalGone)
		return
	}
	t.mu.Lock()
	taken := t.agent != nil
	t.mu.Unlock()
	if taken {
		fail(w, http.StatusConflict, api.ErrTerminalGone)
		return
	}
	conn, err := accept(w, r)
	if err != nil {
		return
	}
	t.mu.Lock()
	if t.agent != nil || t.closed() {
		t.mu.Unlock()
		conn.Close(websocket.StatusPolicyViolation, "taken")
		return
	}
	t.agent = conn
	t.started = time.Now()
	if t.browser == nil {
		t.away = time.AfterFunc(terminalAway, func() { t.end("nobody watching") })
	}
	close(t.ready)
	t.mu.Unlock()
	s.audit(r, t.admin, "terminal.started", fmt.Sprintf("%s %s as %s", t.hostname, t.task, t.user))

	ctx := context.Background()
	limit := time.AfterFunc(time.Duration(t.minutes)*time.Minute+time.Minute, func() { t.end("time is up") })
	defer limit.Stop()
	for {
		kind, data, err := conn.Read(ctx)
		if err != nil {
			t.end(closeReason(err, "device closed"))
			break
		}
		t.toBrowser(kind, data)
	}
	t.mu.Lock()
	reason, started := t.reason, t.started
	t.mu.Unlock()
	s.terminals.remove(t.id)
	s.store.Audit(context.Background(), t.admin, "terminal.ended",
		fmt.Sprintf("%s %s as %s after %s: %s", t.hostname, t.task, t.user, time.Since(started).Round(time.Second), reason))
}

// handleBrowserTerminal is the admin's side. Only the admin who asked for the
// session can watch it, and a new connection replaces the one before.
func (s *Server) handleBrowserTerminal(w http.ResponseWriter, r *http.Request, u store.User) {
	t := s.terminals.get(r.PathValue("session"))
	if t == nil || t.admin != u.Username {
		fail(w, http.StatusNotFound, api.ErrTerminalGone)
		return
	}
	conn, err := accept(w, r)
	if err != nil {
		return
	}
	defer conn.CloseNow()
	ctx := r.Context()
	conn.Write(ctx, websocket.MessageText, []byte(`{"state":"waiting"}`))
	select {
	case <-t.ready:
	case <-t.done:
		conn.Close(websocket.StatusNormalClosure, t.endReason())
		return
	case <-ctx.Done():
		return
	}
	t.mu.Lock()
	if t.closed() {
		t.mu.Unlock()
		conn.Close(websocket.StatusNormalClosure, t.endReason())
		return
	}
	if old := t.browser; old != nil {
		// Closing waits for the other side, which must not hold up the session.
		go old.Close(websocket.StatusNormalClosure, "opened elsewhere")
	}
	t.browser = conn
	resumed := t.watched
	t.watched = true
	if t.away != nil {
		t.away.Stop()
		t.away = nil
	}
	replay := append([]byte(nil), t.replay...)
	agent := t.agent
	t.mu.Unlock()
	if resumed {
		s.audit(r, u.Username, "terminal.resumed", fmt.Sprintf("%s %s as %s", t.hostname, t.task, t.user))
	}
	conn.Write(ctx, websocket.MessageText, []byte(`{"state":"open"}`))
	if len(replay) > 0 {
		conn.Write(ctx, websocket.MessageBinary, replay)
	}
	for {
		kind, data, err := conn.Read(ctx)
		if err != nil {
			break
		}
		if err := agent.Write(context.Background(), kind, data); err != nil {
			break
		}
	}
	t.mu.Lock()
	if t.browser == conn {
		t.browser = nil
		if !t.closed() {
			t.away = time.AfterFunc(terminalAway, func() { t.end("nobody watching") })
		}
	}
	t.mu.Unlock()
}

// runningTerminal is a session the admin can return to.
type runningTerminal struct {
	Session  string    `json:"session"`
	Task     string    `json:"task"`
	Device   string    `json:"device_id"`
	Hostname string    `json:"hostname"`
	User     string    `json:"user"`
	Until    time.Time `json:"until"`
}

// handleTerminals lists the caller's running sessions. Only the admin who
// asked for a session can watch it, so nobody sees those of others.
func (s *Server) handleTerminals(w http.ResponseWriter, _ *http.Request, u store.User) {
	list := []runningTerminal{}
	for _, t := range s.terminals.running(u.Username) {
		t.mu.Lock()
		list = append(list, runningTerminal{Session: t.id, Task: t.task, Device: t.device, Hostname: t.hostname,
			User: t.user, Until: t.started.Add(time.Duration(t.minutes) * time.Minute)})
		t.mu.Unlock()
	}
	slices.SortFunc(list, func(a, b runningTerminal) int { return a.Until.Compare(b.Until) })
	writeJSON(w, http.StatusOK, list)
}

// toBrowser passes on what the device sent, and keeps the end of the output
// for a browser that connects later.
func (t *terminalSession) toBrowser(kind websocket.MessageType, data []byte) {
	t.mu.Lock()
	if kind == websocket.MessageBinary {
		t.replay = append(t.replay, data...)
		if over := len(t.replay) - terminalReplay; over > 0 {
			t.replay = append(t.replay[:0], t.replay[over:]...)
		}
	}
	browser := t.browser
	t.mu.Unlock()
	if browser != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		browser.Write(ctx, kind, data)
	}
}

// closed says whether the session is over. The caller holds the lock.
func (t *terminalSession) closed() bool {
	select {
	case <-t.done:
		return true
	default:
		return false
	}
}

func (t *terminalSession) endReason() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.reason
}

// end closes both sides, once.
func (t *terminalSession) end(reason string) {
	t.mu.Lock()
	if t.closed() {
		t.mu.Unlock()
		return
	}
	t.reason = reason
	close(t.done)
	if t.away != nil {
		t.away.Stop()
	}
	agent, browser := t.agent, t.browser
	t.mu.Unlock()
	// Both close at once: each waits for its other side to answer.
	if browser != nil {
		go browser.Close(websocket.StatusNormalClosure, reason)
	}
	if agent != nil {
		go agent.Close(websocket.StatusNormalClosure, reason)
	}
}

func closeReason(err error, fallback string) string {
	var ce websocket.CloseError
	if errors.As(err, &ce) && ce.Reason != "" {
		return ce.Reason
	}
	return fallback
}
