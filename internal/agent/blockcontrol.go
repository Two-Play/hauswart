package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
)

const (
	// blockControl is where the blocker asks what to show and passes on what
	// the person at the device chose. Only the account of the block may use it.
	blockControl = "/run/hauswart/block/control.sock"
	// blockRequestEvery limits how often more time can be asked for from the block.
	blockRequestEvery = 5 * time.Minute
	maxBlockBody      = 1 << 10
)

// blockMinutes are the choices on the block.
var blockMinutes = []int{15, 30, 60}

// blockControlService answers the blocker. It acts only for the person whose
// screen time the block shows, and only in two ways: ask for more time, or
// log out now.
type blockControlService struct {
	access *Access
	policy *PolicyEngine
	exec   *Executor
	// send files a request as the blocked person, like the desktop app does.
	send func(context.Context, api.DeviceRequest) (string, error)
	// history says how the requests of someone stand.
	history func(user string) api.History
	// blockUID is the account of the block, the only one let in.
	blockUID uint32
	now      func() time.Time
}

func (b *blockControlService) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /state", b.handleState)
	mux.HandleFunc("POST /request", b.handleRequest)
	mux.HandleFunc("POST /logout", b.handleLogout)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, ok := r.Context().Value(peerKey{}).(uint32)
		if !ok || uid != b.blockUID {
			http.Error(w, "only the block may ask", http.StatusForbidden)
			return
		}
		http.MaxBytesHandler(mux, maxBlockBody).ServeHTTP(w, r)
	})
}

// state is what the block shows, with how the last request from it stands.
func (b *blockControlService) state() api.BlockState {
	state := b.access.BlockState()
	if state.Kind != api.BlockScreen || state.RequestedAt.IsZero() || b.history == nil {
		return state
	}
	state.RequestState = api.RequestOpen
	for _, r := range b.history(state.User).Requests {
		if r.Kind == api.RequestScreen && r.CreatedAt >= state.RequestedAt.Add(-time.Minute).Unix() {
			state.RequestState = r.State
		}
	}
	return state
}

func (b *blockControlService) handleState(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(b.state())
}

func (b *blockControlService) handleRequest(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Minutes int `json:"minutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || !containsInt(blockMinutes, in.Minutes) {
		http.Error(w, "minutes must be 15, 30 or 60", http.StatusBadRequest)
		return
	}
	state := b.access.BlockState()
	if state.Kind != api.BlockScreen || state.User == "" {
		http.Error(w, "nobody's screen time is blocked", http.StatusConflict)
		return
	}
	if !b.policy.screenRequested(state.User, b.now(), blockRequestEvery) {
		http.Error(w, "asked a moment ago", http.StatusTooManyRequests)
		return
	}
	status, err := b.send(r.Context(), api.DeviceRequest{User: state.User, UserRequest: api.UserRequest{
		Kind: api.RequestScreen, Detail: strconv.Itoa(in.Minutes), Reason: "asked on the screen time block",
	}})
	var refused *api.Error
	switch {
	case errors.As(err, &refused):
		// Such as no Hauswart account for this Linux user: the server said no.
		http.Error(w, refused.Code, http.StatusUnprocessableEntity)
		return
	case err != nil:
		http.Error(w, "the request did not reach the server", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(api.RequestAnswer{Status: status})
}

// handleLogout ends the sessions of the person behind the block, which also
// lets someone else log in.
func (b *blockControlService) handleLogout(w http.ResponseWriter, r *http.Request) {
	state := b.access.BlockState()
	if state.Kind != api.BlockScreen || state.User == "" {
		http.Error(w, "nobody's screen time is blocked", http.StatusConflict)
		return
	}
	if out, err := b.exec.Run(r.Context(), "loginctl", "terminate-user", state.User); err != nil {
		http.Error(w, "logging out failed: "+clip(out, maxDeviationText), http.StatusInternalServerError)
		return
	}
	b.access.loggedOut(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// listenBlockControl opens the socket for the account of the block alone.
func listenBlockControl(path string, uid int) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chown(path, uid, 0); err == nil {
		err = os.Chmod(path, 0o600)
	}
	if err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}

// serveBlockControl runs while the agent does. Without the account of the
// block there is no block to answer, and it waits for one.
func (a *Agent) serveBlockControl(ctx context.Context, path string) {
	var account *user.User
	for {
		var err error
		if account, err = user.Lookup(blockUser); err == nil {
			break
		}
		// The block sets its account up the first time it is needed, and then
		// asks at once; a long wait would leave it without its words.
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return
	}
	listener, err := listenBlockControl(path, uid)
	if err != nil {
		a.log.Warn("the socket of the full-screen block is off", "err", err)
		return
	}
	service := &blockControlService{access: a.access, policy: a.policy, exec: a.exec, send: a.sendRequest,
		history: a.notices.History, blockUID: uint32(uid), now: time.Now}
	server := &http.Server{
		Handler:           service.handler(),
		ReadHeaderTimeout: userTimeout,
		ReadTimeout:       userTimeout,
		WriteTimeout:      userTimeout,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			if peer, err := peerUID(conn); err == nil {
				return context.WithValue(ctx, peerKey{}, peer)
			}
			return ctx
		},
	}
	go func() {
		<-ctx.Done()
		server.Close()
	}()
	if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
		a.log.Warn("the socket of the full-screen block stopped", "err", err)
	}
}

// greeterTTY is the console of the login screen, empty if there is none.
func (e *Executor) greeterTTY(ctx context.Context) string {
	out, err := e.Run(ctx, "loginctl", "list-sessions", "--no-legend")
	if err != nil {
		return ""
	}
	for line := range strings.Lines(out) {
		fields := strings.Fields(line)
		if len(fields) == 0 || !sessionIDRe.MatchString(fields[0]) {
			continue
		}
		shown, err := e.Run(ctx, "loginctl", "show-session", fields[0], "-p", "Class", "-p", "VTNr")
		if err != nil {
			continue
		}
		props := parseProperties(shown)
		if props["Class"] == "greeter" && props["VTNr"] != "" && props["VTNr"] != "0" {
			return "tty" + props["VTNr"]
		}
	}
	return ""
}

// loggedOut sends the screen back to the login screen once the person behind
// the block is gone, not to the console their session left.
func (a *Access) loggedOut(ctx context.Context) {
	a.mu.Lock()
	a.blockedFor = ""
	a.returnTo = ""
	a.mu.Unlock()
	a.hideBlock(ctx)
	// The display manager starts its login screen anew; give it a moment.
	for range 10 {
		if tty := a.exec.greeterTTY(ctx); tty != "" {
			a.exec.Run(ctx, "chvt", strings.TrimPrefix(tty, "tty"))
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}
