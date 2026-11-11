package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/Two-Play/hauswart/internal/store"
)

// An admin who closed the window finds the session again, with what it missed,
// and nobody else sees it.
func TestTerminalCanBeResumed(t *testing.T) {
	e := setup(t)
	_, agent, admin, opened := openTerminal(t, e)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	running := func(c *http.Client) []runningTerminal {
		code, data := e.do(c, "GET", "/api/terminals", nil)
		var list []runningTerminal
		if code != http.StatusOK || json.Unmarshal(data, &list) != nil {
			t.Fatalf("%d %s", code, data)
		}
		return list
	}
	if list := running(admin); len(list) != 0 {
		t.Fatalf("listed before the device connected: %+v", list)
	}

	browser, _, err := e.dial(admin, "/api/terminal/"+opened.Session, nil)
	if err != nil {
		t.Fatal(err)
	}
	readText(t, browser)
	device, _, err := e.dial(agent, "/agent/terminal/"+opened.Session, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer device.CloseNow()
	readText(t, browser)

	list := running(admin)
	if len(list) != 1 || list[0].Session != opened.Session || list[0].User != "root" || time.Until(list[0].Until) < 4*time.Minute {
		t.Fatalf("%+v", list)
	}
	e.addUser("other", "other", store.RoleAdmin)
	if others := running(e.login("other")); len(others) != 0 {
		t.Fatalf("another admin sees %+v", others)
	}

	// The window closes; the shell goes on and its output is kept.
	browser.Close(websocket.StatusNormalClosure, "")
	if err := device.Write(ctx, websocket.MessageBinary, []byte("still here\r\n")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if list := running(admin); len(list) != 1 {
		t.Fatalf("ended without a browser: %+v", list)
	}

	again, _, err := e.dial(admin, "/api/terminal/"+opened.Session, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer again.CloseNow()
	readText(t, again)
	readText(t, again)
	if _, data, err := again.Read(ctx); err != nil || string(data) != "still here\r\n" {
		t.Fatalf("replay %q %v", data, err)
	}
	entries, _ := e.store.ListAudit(context.Background(), 20)
	resumed := false
	for _, a := range entries {
		resumed = resumed || (a.Action == "terminal.resumed" && a.Actor == "admin")
	}
	if !resumed {
		t.Fatalf("no audit entry: %+v", entries)
	}
}
