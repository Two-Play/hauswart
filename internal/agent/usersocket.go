package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/catalog"
)

const (
	userSocket = "/run/hauswart/user.sock"
	// A request is short, and everything on this socket comes from someone who
	// has no rights here.
	maxUserBody     = 4 << 10
	userRequestsMax = 10
	userSearchesMax = 60
	userRequestSpan = time.Hour
	userTimeout     = 10 * time.Second
	// Anyone on the device can reach this socket, and the agent has more important
	// things to do. A member must not be able to starve it of processes or files,
	// which is what the end of a session needs as well.
	maxUserConns   = 16
	maxUserPerUID  = 4
	userStatusKeep = 5 * time.Second
	userNameKeep   = time.Minute
	lookupTimeout  = 5 * time.Second
)

type peerKey struct{}

// peerUID asks the kernel who is on the other side. Nothing a client says about
// itself counts.
func peerUID(conn net.Conn) (uint32, error) {
	if limited, ok := conn.(*limitedConn); ok {
		conn = limited.Conn
	}
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
	// send hands a request to the server and returns its status, approved
	// when a rule approved it at once.
	send func(context.Context, api.DeviceRequest) (string, error)
	// search finds packages or Flatpaks through the server.
	search func(ctx context.Context, kind, q string) ([]catalog.Entry, error)
	now    func() time.Time

	mu       sync.Mutex
	asked    map[uint32][]time.Time
	searched map[uint32][]time.Time
	active   map[uint32]int
	names    map[uint32]knownName
	recent   map[uint32]recentStatus
}

type knownName struct {
	name string
	at   time.Time
}

// recentStatus keeps an answer for a moment, so that asking in a loop costs nothing.
type recentStatus struct {
	status api.UserStatus
	at     time.Time
}

// limitedListener holds new connections back while too many are open.
type limitedListener struct {
	net.Listener
	slots chan struct{}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	l.slots <- struct{}{}
	conn, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &limitedConn{Conn: conn, release: func() { <-l.slots }}, nil
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}

// perUser refuses someone who already has enough going on.
func (u *userService) perUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, ok := r.Context().Value(peerKey{}).(uint32)
		if !ok {
			http.Error(w, "unknown user", http.StatusForbidden)
			return
		}
		u.mu.Lock()
		busy := u.active[uid] >= maxUserPerUID
		if !busy {
			u.active[uid]++
		}
		u.mu.Unlock()
		if busy {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		defer func() {
			u.mu.Lock()
			defer u.mu.Unlock()
			u.active[uid]--
		}()
		next.ServeHTTP(w, r)
	})
}

// allow is a sliding limit per person, as a loop on a desktop must not fill the
// inbox of the approvers.
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
	mux.HandleFunc("GET /search", u.handleSearch)
	return u.perUser(http.MaxBytesHandler(mux, maxUserBody))
}

func (u *userService) peerName(r *http.Request) (uint32, string, bool) {
	uid, ok := r.Context().Value(peerKey{}).(uint32)
	if !ok {
		return 0, "", false
	}
	now := u.now()
	u.mu.Lock()
	known, found := u.names[uid]
	u.mu.Unlock()
	if found && now.Sub(known.at) < userNameKeep {
		return uid, known.name, true
	}
	name, ok := u.exec.userName(r.Context(), strconv.FormatUint(uint64(uid), 10))
	if ok {
		u.mu.Lock()
		u.names[uid] = knownName{name, now}
		u.mu.Unlock()
	}
	return uid, name, ok
}

// userName finds an account by its ID, like lookupUser by its name. /etc/passwd
// comes first, as that needs no process.
func (e *Executor) userName(ctx context.Context, uid string) (string, bool) {
	if u, err := user.LookupId(uid); err == nil {
		return u.Username, true
	}
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	out, err := e.Run(ctx, "getent", "passwd", uid)
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
	now := u.now()
	u.mu.Lock()
	recent, found := u.recent[uid]
	u.mu.Unlock()
	status := recent.status
	if !found || now.Sub(recent.at) >= userStatusKeep {
		id := strconv.FormatUint(uint64(uid), 10)
		status = api.UserStatus{
			User:       name,
			ScreenTime: u.policy.ScreenStatus(id, now),
			Shares:     u.exec.mountedShares(name, id),
			Dashboard:  u.dashboard,
		}
		status.PolicyIssues, status.Nextcloud = u.policy.userView()
		u.mu.Lock()
		u.recent[uid] = recentStatus{status, now}
		u.mu.Unlock()
	}
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
	status, err := u.send(r.Context(), api.DeviceRequest{User: name, UserRequest: in})
	var refused *api.Error
	switch {
	case errors.As(err, &refused):
		// A request the server refused did not bother anyone.
		u.giveBack(uid)
		http.Error(w, refused.Code, http.StatusUnprocessableEntity)
	case err != nil:
		u.giveBack(uid)
		http.Error(w, "the server cannot be reached", http.StatusBadGateway)
	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(api.RequestAnswer{Status: status})
	}
}

// handleSearch helps someone find the name of what they ask for. Typing sends a
// search per pause, so the limit is higher than for requests, and an empty
// list is the answer to anything that goes wrong.
func (u *userService) handleSearch(w http.ResponseWriter, r *http.Request) {
	uid, _, ok := u.peerName(r)
	if !ok {
		http.Error(w, "unknown user", http.StatusForbidden)
		return
	}
	kind := r.URL.Query().Get("kind")
	q, worth := catalog.NormalizeQuery(r.URL.Query().Get("q"))
	if kind != api.SearchPackage && kind != api.SearchFlatpak {
		http.Error(w, "invalid search", http.StatusBadRequest)
		return
	}
	entries := []catalog.Entry{}
	if worth && u.search != nil && u.allowSearch(uid, u.now()) {
		found, err := u.search(r.Context(), kind, q)
		if err == nil {
			entries = found
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

func (u *userService) allowSearch(uid uint32, now time.Time) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.searched == nil {
		u.searched = map[uint32][]time.Time{}
	}
	recent := slices.DeleteFunc(u.searched[uid], func(at time.Time) bool { return !now.Before(at.Add(time.Minute)) })
	if len(recent) >= userSearchesMax {
		u.searched[uid] = recent
		return false
	}
	u.searched[uid] = append(recent, now)
	return true
}

func (u *userService) giveBack(uid uint32) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if asked := u.asked[uid]; len(asked) > 0 {
		u.asked[uid] = asked[:len(asked)-1]
	}
}

// mountedShares lists the shares of a person, by their folder in /media. The owner
// comes from the mount options, as another name can start like this one.
func (e *Executor) mountedShares(name, uid string) []string {
	raw, err := os.ReadFile(e.path("/proc/mounts"))
	if err != nil {
		return nil
	}
	prefix := "/media/" + name + "-"
	var shares []string
	for line := range strings.Lines(string(raw)) {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[2] != "cifs" {
			continue
		}
		folder, ok := strings.CutPrefix(fields[1], prefix)
		if ok && slices.Contains(strings.Split(fields[3], ","), "uid="+uid) {
			shares = append(shares, folder)
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
	listener = &limitedListener{Listener: listener, slots: make(chan struct{}, maxUserConns)}
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
	server.SetKeepAlivesEnabled(false)
	go func() {
		<-ctx.Done()
		server.Close()
	}()
	if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// sendRequest hands a request to the server and returns the status it got. An
// *api.Error says that the server refused the request, which is something else
// than not reaching it.
func (a *Agent) sendRequest(ctx context.Context, r api.DeviceRequest) (string, error) {
	body, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.Server+"/agent/requests", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 300 {
		var answer api.RequestAnswer
		// An older server says nothing, which means that someone decides.
		json.NewDecoder(io.LimitReader(resp.Body, maxUserBody)).Decode(&answer)
		return answer.Normalized(), nil
	}
	if resp.StatusCode >= 500 {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	var answer struct {
		Code string `json:"code"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, maxUserBody)).Decode(&answer)
	return "", api.Fail(answer.Code)
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
		active:    map[uint32]int{},
		names:     map[uint32]knownName{},
		recent:    map[uint32]recentStatus{},
		send:      a.sendRequest,
		search:    a.search,
	}
	if err := service.serve(ctx, listener); err != nil {
		a.log.Warn("the socket for desktop apps stopped", "err", err)
	}
}
