package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coder/websocket"
	"github.com/creack/pty"

	"github.com/Two-Play/hauswart/internal/api"
)

const (
	// maxTerminals caps the shells that run at once.
	maxTerminals = 2
	// terminalKillWait is how long a shell has to end after the hangup.
	terminalKillWait = 5 * time.Second
	terminalFrame    = 32 << 10
	maxTerminalSize  = 1000
)

// terminalIdle ends a session nobody typed in for this long. Tests shorten it.
var terminalIdle = 15 * time.Minute

// terminalRun is one live shell, for the desktop app and the log.
type terminalRun struct {
	User     string    `json:"user"`
	Approver string    `json:"approver"`
	Since    time.Time `json:"since"`
	Until    time.Time `json:"until"`
}

type terminals struct {
	mu      sync.Mutex
	running map[string]terminalRun
}

func (t *terminals) add(session string, run terminalRun) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.running == nil {
		t.running = map[string]terminalRun{}
	}
	if len(t.running) >= maxTerminals {
		return false
	}
	t.running[session] = run
	return true
}

func (t *terminals) remove(session string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.running, session)
}

// current is the session that started first, nil if none runs.
func (t *terminals) current() *api.TerminalStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	var first *api.TerminalStatus
	for _, run := range t.running {
		if first == nil || run.Since.Before(first.Since) {
			first = &api.TerminalStatus{User: run.User, Approver: run.Approver, Since: run.Since, Until: run.Until}
		}
	}
	return first
}

// approverName is who let a session in: the passkey the device pinned, or a
// signature, whose key has no name of its own.
func approverName(task api.Task) string {
	if task.Approver != "" {
		return task.Approver
	}
	return "hauswart-admin"
}

// openTerminal connects to the session the server waits for and starts the
// shell. It returns once both are up; the session runs on its own after that.
func (a *Agent) openTerminal(ctx context.Context, task api.Task) api.TaskResult {
	if a.guard == nil {
		// Without pinned keys, nothing but the server would decide.
		return api.TaskResult{OK: false, Output: "a live terminal needs a protected device"}
	}
	if err := api.Validate(task.Type, task.Payload); err != nil {
		return api.TaskResult{OK: false, Output: err.Error()}
	}
	var p api.TerminalPayload
	if err := json.Unmarshal(task.Payload, &p); err != nil {
		return api.TaskResult{OK: false, Output: err.Error()}
	}
	if err := terminalAccount(p.User); err != nil {
		return api.TaskResult{OK: false, Output: err.Error()}
	}
	now := time.Now()
	run := terminalRun{User: p.User, Approver: approverName(task), Since: now, Until: now.Add(time.Duration(p.Minutes) * time.Minute)}
	if !a.terminals.add(p.Session, run) {
		return api.TaskResult{OK: false, Output: fmt.Sprintf("%d terminals are open already", maxTerminals)}
	}
	conn, err := a.dialTerminal(ctx, p.Session)
	if err != nil {
		a.terminals.remove(p.Session)
		return api.TaskResult{OK: false, Output: "connecting to the server failed: " + err.Error()}
	}
	cmd := terminalCommand(p.User)
	tty, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 24, Cols: 80})
	if err != nil {
		conn.Close(websocket.StatusInternalError, "the shell did not start")
		a.terminals.remove(p.Session)
		return api.TaskResult{OK: false, Output: "starting the shell failed: " + err.Error()}
	}
	a.log.Warn("live terminal opened", "id", task.ID, "user", p.User, "approver", run.Approver, "minutes", p.Minutes)
	if a.notices != nil {
		a.notices.record(ctx, api.DeviceEvent{Kind: api.EventTerminalStarted, Detail: p.User + " · " + run.Approver, Until: run.Until}, urgencyCritical)
	}
	go func() {
		reason := a.runTerminal(conn, cmd, tty, run.Until)
		a.terminals.remove(p.Session)
		a.log.Warn("live terminal closed", "id", task.ID, "user", p.User, "approver", run.Approver,
			"after", time.Since(now).Round(time.Second).String(), "reason", reason)
		if a.notices != nil {
			a.notices.record(context.Background(), api.DeviceEvent{Kind: api.EventTerminalEnded}, urgencyNormal)
		}
	}()
	return api.TaskResult{OK: true, Output: fmt.Sprintf("live terminal opened as %s for at most %d minutes", p.User, p.Minutes)}
}

// terminalAccount checks that the account exists and is root or a person's.
func terminalAccount(name string) error {
	account, err := user.Lookup(name)
	if err != nil {
		return fmt.Errorf("no account %s on this device", name)
	}
	if name != api.TerminalRoot {
		if uid, _ := strconv.Atoi(account.Uid); uid < minUserUID || uid >= nobodyUID {
			return fmt.Errorf("%s is a system account", name)
		}
	}
	return nil
}

// terminalCommand starts a login shell of the account, as su - would, which
// starts at home. pty gives it a session of its own, so that its end reaches
// everything in it.
func terminalCommand(name string) *exec.Cmd {
	cmd := exec.Command("runuser", "-l", name)
	cmd.Dir = "/"
	cmd.Env = []string{"TERM=xterm-256color", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	if lang := os.Getenv("LANG"); lang != "" {
		cmd.Env = append(cmd.Env, "LANG="+lang)
	}
	return cmd
}

func (a *Agent) dialTerminal(ctx context.Context, session string) (*websocket.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	// The client of the polls has a timeout that would end the session.
	client := &http.Client{Transport: a.client.Transport}
	conn, _, err := websocket.Dial(ctx, a.cfg.Server+"/agent/terminal/"+session, &websocket.DialOptions{HTTPClient: client})
	if err != nil {
		return nil, err
	}
	conn.SetReadLimit(terminalFrame)
	return conn, nil
}

// terminalControl is what a browser sends besides keystrokes.
type terminalControl struct {
	Resize *struct {
		Cols int `json:"cols"`
		Rows int `json:"rows"`
	} `json:"resize,omitempty"`
}

// runTerminal passes data between the connection and the shell until one of
// them ends, the time is up or nobody typed for too long. It says why it ended.
func (a *Agent) runTerminal(conn *websocket.Conn, cmd *exec.Cmd, tty *os.File, until time.Time) string {
	// A cancelled context would close the connection at once, before the exit
	// code is out, so the end is a channel of its own.
	ctx := context.Background()
	stopped := make(chan struct{})
	var once sync.Once
	reason := ""
	stop := func(why string) {
		once.Do(func() {
			reason = why
			close(stopped)
		})
	}

	// The shell's output goes to the server.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		buf := make([]byte, terminalFrame)
		for {
			n, err := tty.Read(buf)
			if n > 0 {
				if werr := conn.Write(ctx, websocket.MessageBinary, buf[:n]); werr != nil {
					stop("connection lost")
					return
				}
			}
			if err != nil {
				stop("shell ended")
				return
			}
		}
	}()

	// Keystrokes and resizes come from the server.
	typed := make(chan struct{}, 1)
	go func() {
		for {
			kind, data, err := conn.Read(ctx)
			if err != nil {
				stop(closeText(err))
				return
			}
			if kind == websocket.MessageBinary {
				if _, err := tty.Write(data); err != nil {
					stop("shell ended")
					return
				}
				select {
				case typed <- struct{}{}:
				default:
				}
				continue
			}
			var control terminalControl
			if json.Unmarshal(data, &control) == nil && control.Resize != nil {
				cols, rows := control.Resize.Cols, control.Resize.Rows
				if cols > 0 && rows > 0 && cols <= maxTerminalSize && rows <= maxTerminalSize {
					pty.Setsize(tty, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
				}
			}
		}
	}()

	exited := make(chan int, 1)
	go func() {
		err := cmd.Wait()
		code := 0
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
			// A shell that a signal ended reports it as 128 and the signal, as
			// shells do. -1 stays for a shell that has not ended.
			if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() {
				code = 128 + int(status.Signal())
			}
		}
		exited <- code
	}()

	idle := time.NewTimer(terminalIdle)
	defer idle.Stop()
	deadline := time.NewTimer(time.Until(until))
	defer deadline.Stop()
	code := -1
loop:
	for {
		select {
		case <-typed:
			if !idle.Stop() {
				select {
				case <-idle.C:
				default:
				}
			}
			idle.Reset(terminalIdle)
		case <-idle.C:
			stop("nobody typed for " + terminalIdle.String())
			break loop
		case <-deadline.C:
			stop("time is up")
			break loop
		case code = <-exited:
			stop("shell ended")
			// What the shell wrote last is still on its way.
			select {
			case <-drained:
			case <-time.After(time.Second):
			}
			break loop
		case <-stopped:
			break loop
		}
	}

	// Closing the terminal hangs up on the shell, as closing an SSH login
	// would. Whatever still runs in the session gets the hangup as well, then
	// the kill.
	tty.Close()
	endSession(cmd.Process.Pid, exited, &code)
	if code >= 0 {
		end, _ := json.Marshal(map[string]int{"exit": code})
		writeCtx, done := context.WithTimeout(context.Background(), 2*time.Second)
		conn.Write(writeCtx, websocket.MessageText, end)
		done()
	}
	conn.Close(websocket.StatusNormalClosure, reason)
	return reason
}

// endSession hangs up on every process of the session the shell leads, and
// kills what is left after a moment.
func endSession(sid int, exited chan int, code *int) {
	signalSession(sid, syscall.SIGHUP)
	if *code < 0 {
		select {
		case *code = <-exited:
		case <-time.After(terminalKillWait):
		}
	}
	signalSession(sid, syscall.SIGKILL)
	if *code < 0 {
		select {
		case *code = <-exited:
		case <-time.After(terminalKillWait):
		}
	}
}

// signalSession signals every process whose session is sid. A process that
// started a session of its own got away, as it would from a closed SSH login.
func signalSession(sid int, sig syscall.Signal) {
	pids, _ := readProcPids()
	for _, pid := range pids {
		if processSession(pid) == sid {
			syscall.Kill(pid, sig)
		}
	}
}

// readProcPids lists the processes that run now.
func readProcPids() ([]int, error) {
	entries, err := os.ReadDir("/proc")
	pids := make([]int, 0, len(entries))
	for _, entry := range entries {
		if pid, err := strconv.Atoi(entry.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids, err
}

// processSession reads the session of a process from /proc, -1 if it is gone.
func processSession(pid int) int {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return -1
	}
	// The name in parentheses may hold spaces, so the fields start after it.
	end := strings.LastIndexByte(string(raw), ')')
	if end < 0 {
		return -1
	}
	fields := strings.Fields(string(raw[end+1:]))
	// state ppid pgrp session
	if len(fields) < 4 {
		return -1
	}
	sid, err := strconv.Atoi(fields[3])
	if err != nil {
		return -1
	}
	return sid
}

func closeText(err error) string {
	var ce websocket.CloseError
	if errors.As(err, &ce) && ce.Reason != "" {
		return ce.Reason
	}
	if errors.Is(err, io.EOF) {
		return "connection closed"
	}
	return "connection lost"
}
