package agent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/creack/pty"
)

// shellSession runs a shell of the current user under runTerminal, with the
// test as the server's side of the connection.
func shellSession(t *testing.T, until time.Time) (*websocket.Conn, chan string, *exec.Cmd) {
	t.Helper()
	sides := make(chan *websocket.Conn, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		sides <- conn
		<-r.Context().Done()
	}))
	t.Cleanup(ts.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	device, _, err := websocket.Dial(ctx, ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := <-sides
	t.Cleanup(func() { server.CloseNow() })
	cmd := exec.Command("/bin/sh")
	cmd.Env = []string{"PS1=$ ", "PATH=/usr/bin:/bin"}
	tty, err := pty.Start(cmd)
	if err != nil {
		t.Fatal(err)
	}
	ended := make(chan string, 1)
	a := &Agent{log: quiet()}
	go func() { ended <- a.runTerminal(device, cmd, tty, until) }()
	return server, ended, cmd
}

// readUntil collects the output of the shell until it holds want.
func readUntil(t *testing.T, conn *websocket.Conn, want string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var out strings.Builder
	for !strings.Contains(out.String(), want) {
		kind, data, err := conn.Read(ctx)
		if err != nil {
			return out.String(), err
		}
		if kind == websocket.MessageBinary {
			out.Write(data)
		} else {
			out.WriteString("\n<" + string(data) + ">\n")
		}
	}
	return out.String(), nil
}

func TestTerminalRunsAShell(t *testing.T) {
	server, ended, _ := shellSession(t, time.Now().Add(time.Minute))
	ctx := context.Background()
	server.Write(ctx, websocket.MessageText, []byte(`{"resize":{"cols":100,"rows":40}}`))
	server.Write(ctx, websocket.MessageBinary, []byte("echo hi-$((40+2)); stty size\n"))
	if out, err := readUntil(t, server, "40 100"); err != nil || !strings.Contains(out, "hi-42") {
		t.Fatalf("got %q %v", out, err)
	}
	server.Write(ctx, websocket.MessageBinary, []byte("exit 3\n"))
	out, err := readUntil(t, server, `{"exit":3}`)
	if err != nil {
		t.Fatalf("got %q %v", out, err)
	}
	_, _, err = server.Read(ctx)
	var ce websocket.CloseError
	if !errors.As(err, &ce) || ce.Reason != "shell ended" {
		t.Fatalf("close: %v", err)
	}
	if reason := <-ended; reason != "shell ended" {
		t.Fatalf("ended: %s", reason)
	}
}

func TestTerminalEndsWhenTimeIsUpAndTakesItsChildren(t *testing.T) {
	server, ended, cmd := shellSession(t, time.Now().Add(time.Second))
	ctx := context.Background()
	server.Write(ctx, websocket.MessageBinary, []byte("sleep 300 & echo started\n"))
	if out, err := readUntil(t, server, "started"); err != nil {
		t.Fatalf("got %q %v", out, err)
	}
	go drain(server)
	select {
	case reason := <-ended:
		if reason != "time is up" {
			t.Fatalf("ended: %s", reason)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the session outlived its time")
	}
	sid := cmd.Process.Pid
	deadline := time.Now().Add(5 * time.Second)
	for sessionAlive(sid) {
		if time.Now().After(deadline) {
			t.Fatal("a process of the session is still there")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestTerminalEndsWhenNobodyTypes(t *testing.T) {
	before := terminalIdle
	terminalIdle = 300 * time.Millisecond
	t.Cleanup(func() { terminalIdle = before })
	server, ended, _ := shellSession(t, time.Now().Add(time.Minute))
	go drain(server)
	select {
	case reason := <-ended:
		if !strings.HasPrefix(reason, "nobody typed") {
			t.Fatalf("ended: %s", reason)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("an idle session stays open")
	}
}

func TestTerminalEndsWhenTheServerGoes(t *testing.T) {
	server, ended, _ := shellSession(t, time.Now().Add(time.Minute))
	server.Close(websocket.StatusNormalClosure, "nobody watching")
	select {
	case reason := <-ended:
		if reason != "nobody watching" {
			t.Fatalf("ended: %s", reason)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the shell outlived the connection")
	}
}

func sessionAlive(sid int) bool {
	entries, _ := readProcPids()
	for _, pid := range entries {
		if processSession(pid) == sid {
			return true
		}
	}
	return false
}

// drain reads what the shell sends, as the server does, so that closing does
// not wait for an answer.
func drain(conn *websocket.Conn) {
	for {
		if _, _, err := conn.Read(context.Background()); err != nil {
			return
		}
	}
}
