package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
)

const (
	userSocket = "/run/hauswart/user.sock"
	// A request is short, and everything on this socket comes from someone who
	// has no rights here.
	maxUserBody     = 4 << 10
	userRequestsMax = 10
	userRequestSpan = time.Hour
	userTimeout     = 10 * time.Second
)

type peerKey struct{}

// peerUID asks the kernel who is on the other side. Nothing a client says about
// itself counts.
func peerUID(conn net.Conn) (uint32, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, errors.New("not a unix socket")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, credErr
	}
	return cred.Uid, nil
}

// userService answers the desktop apps on a device.
type userService struct {
	exec      *Executor
	policy    *PolicyEngine
	dashboard string
	// send hands a request to the server.
	send func(context.Context, api.DeviceRequest) error
	now  func() time.Time

	mu    sync.Mutex
	asked map[uint32][]time.Time
}

// allow is a sliding limit per person, as a loop on a desktop must not fill the
// inbox of the parents.
func (u *userService) allow(uid uint32, now time.Time) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	recent := slices.DeleteFunc(u.asked[uid], func(at time.Time) bool { return !now.Before(at.Add(userRequestSpan)) })
	if len(recent) >= userRequestsMax {
		u.asked[uid] = recent
		return false
	}
	u.asked[uid] = append(recent, now)
	return true
}

func (u *userService) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", u.handleStatus)
	mux.HandleFunc("POST /request", u.handleRequest)
	return http.MaxBytesHandler(mux, maxUserBody)
}

func (u *userService) peerName(r *http.Request) (uint32, string, bool) {
	uid, ok := r.Context().Value(peerKey{}).(uint32)
	if !ok {
		return 0, "", false
	}
	name, ok := u.exec.userName(strconv.FormatUint(uint64(uid), 10))
	return uid, name, ok
}

// userName finds an account by its ID, like lookupUser by its name.
func (e *Executor) userName(uid string) (string, bool) {
	out, err := e.Run(context.Background(), "getent", "passwd", uid)
	if err != nil {
		return "", false
	}
	name, _, ok := strings.Cut(strings.TrimSpace(out), ":")
	return name, ok && name != ""
}

func (u *userService) handleStatus(w http.ResponseWriter, r *http.Request) {
	uid, name, ok := u.peerName(r)
	if !ok {
		http.Error(w, "unknown user", http.StatusForbidden)
		return
	}
	status := api.UserStatus{
		User:       name,
		ScreenTime: u.policy.ScreenStatus(strconv.FormatUint(uint64(uid), 10), u.now()),
		Shares:     u.exec.mountedShares(name),
		Dashboard:  u.dashboard,
	}
	status.PolicyIssues, status.Nextcloud = u.policy.userView()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (u *userService) handleRequest(w http.ResponseWriter, r *http.Request) {
	uid, name, ok := u.peerName(r)
	if !ok {
		http.Error(w, "unknown user", http.StatusForbidden)
		return
	}
	var in api.UserRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if err := api.CheckUserRequest(in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !u.allow(uid, u.now()) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	if err := u.send(r.Context(), api.DeviceRequest{User: name, UserRequest: in}); err != nil {
		http.Error(w, "the server cannot be reached", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// mountedShares lists the shares of a person, by their folder in /media.
func (e *Executor) mountedShares(name string) []string {
	raw, err := os.ReadFile(e.path("/proc/mounts"))
	if err != nil {
		return nil
	}
	prefix := "/media/" + name + "-"
	var shares []string
	for line := range strings.Lines(string(raw)) {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[2] == "cifs" {
			if folder, ok := strings.CutPrefix(fields[1], prefix); ok {
				shares = append(shares, folder)
			}
		}
	}
	return shares
}

// userView is what a person learns about the policy of the device.
func (pe *PolicyEngine) userView() (bool, *api.NextcloudRule) {
	status := pe.Status()
	issues := status != nil && len(status.Deviations) > 0
	pe.mu.Lock()
	defer pe.mu.Unlock()
	if pe.policy == nil {
		return issues, nil
	}
	return issues, pe.policy.Nextcloud
}

func listenUsers(path string) (net.Listener, error) {
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
	// Everyone on the device may ask, about themselves.
	if err := os.Chmod(path, 0o666); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}

func (u *userService) serve(ctx context.Context, listener net.Listener) error {
	server := &http.Server{
		Handler:           u.handler(),
		ReadHeaderTimeout: userTimeout,
		ReadTimeout:       userTimeout,
		WriteTimeout:      userTimeout,
		MaxHeaderBytes:    maxUserBody,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			uid, err := peerUID(conn)
			if err != nil {
				return ctx
			}
			return context.WithValue(ctx, peerKey{}, uid)
		},
	}
	go func() {
		<-ctx.Done()
		server.Close()
	}()
	if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// serveUsers must never take the agent down: desktops are a convenience.
func (a *Agent) serveUsers(ctx context.Context, path string) {
	listener, err := listenUsers(path)
	if err != nil {
		a.log.Warn("the socket for desktop apps is off", "err", err)
		return
	}
	service := &userService{
		exec:      a.exec,
		policy:    a.policy,
		dashboard: a.cfg.Server,
		now:       time.Now,
		asked:     map[uint32][]time.Time{},
		send: func(ctx context.Context, r api.DeviceRequest) error {
			return a.post(ctx, "/agent/requests", r)
		},
	}
	if err := service.serve(ctx, listener); err != nil {
		a.log.Warn("the socket for desktop apps stopped", "err", err)
	}
}
