package admintool

import (
	"strings"
	"testing"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
)

func TestPrepareAddsContext(t *testing.T) {
	cfg := &config{Devices: map[string]*device{"dev": {Name: "laptop"}}}
	task := install("vim")
	task.CreatedBy = "auto:anna"
	task.CreatedAt = 1700000000
	task.Hostname = "lap\x1btop"
	task.LastSeen = 1700000100
	task.Sessions = []api.LoginSession{{User: "anna", Active: true}, {User: "b‮ob"}}
	task.Request = &queuedRequest{User: "anna", Reason: "for\nschool\x07 ‮please", CreatedAt: 1699999900}
	item := prepare(cfg, nil, task, nil)
	if item.Problem != "" {
		t.Fatal(item.Problem)
	}
	if !item.CreatedAt.Equal(time.Unix(1700000000, 0)) || !item.LastSeen.Equal(time.Unix(1700000100, 0)) || !item.Automatic() {
		t.Fatalf("times: %+v", item)
	}
	if item.Hostname != "lap�top" || len(item.Sessions) != 2 || item.Sessions[1].User != "b�ob" || !item.Sessions[0].Active {
		t.Fatalf("device: %q %+v", item.Hostname, item.Sessions)
	}
	r := item.Request
	if r == nil || r.User != "anna" || r.Reason != "for school� �please" || !r.At.Equal(time.Unix(1699999900, 0)) {
		t.Fatalf("request: %+v", r)
	}
	// Context is not what is signed: it may change while the admin reads.
	other := task
	other.LastSeen = 1700000500
	other.Sessions = nil
	if prepare(cfg, nil, other, nil).digest() != item.digest() {
		t.Fatal("context changed the digest")
	}
}

func TestPrepareWithoutRequest(t *testing.T) {
	cfg := &config{Devices: map[string]*device{"dev": {Name: "laptop"}}}
	item := prepare(cfg, nil, install("vim"), nil)
	if item.Request != nil || !item.CreatedAt.IsZero() || item.Automatic() {
		t.Fatalf("%+v", item)
	}
}

func TestContextLines(t *testing.T) {
	now := time.Date(2026, 11, 10, 21, 32, 0, 0, time.Local)
	item := Item{
		CreatedBy: "admin",
		CreatedAt: time.Date(2026, 11, 10, 21, 30, 0, 0, time.Local),
		Request:   &Request{User: "anna", Reason: "homework", At: time.Date(2026, 11, 10, 21, 28, 0, 0, time.Local)},
		Hostname:  "laptop",
		LastSeen:  now.Add(-2 * time.Minute),
		Sessions:  []LoggedIn{{User: "anna", Active: true}, {User: "ben"}},
	}
	got := strings.Join(contextLines(item, now), "\n")
	want := "Created 10.11. 21:30 by admin\nRequested by anna on 10.11. 21:28: “homework”\nDevice: laptop · last seen 2 min ago · logged in: anna (active), ben"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	item.CreatedBy = "auto:anna"
	item.Request = nil
	item.Sessions = nil
	item.LastSeen = time.Time{}
	got = strings.Join(contextLines(item, now), "\n")
	want = "Created 10.11. 21:30, approved automatically by a rule\nDevice: laptop · never seen"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}
