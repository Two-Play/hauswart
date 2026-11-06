package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
)

type userEnv struct {
	service *userService
	client  *http.Client
	system  *loginSystem
	sent    []api.DeviceRequest
	name    string
	uid     string
}

// newUserEnv serves on a real socket, so that the kernel says who is calling.
func newUserEnv(t *testing.T) *userEnv {
	t.Helper()
	pe, system, name := newScreenEngine(t)
	me, err := user.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	system.accounts = map[string]string{me.Uid: "", name: me.Uid}
	pe.exec.Run = func(ctx context.Context, cmd string, args ...string) (string, error) {
		if cmd == "getent" && args[1] == me.Uid {
			return name + ":x:" + me.Uid + ":" + me.Uid + "::/home/x:/bin/bash\n", nil
		}
		return system.run(ctx, cmd, args...)
	}
	env := &userEnv{system: system, name: name, uid: me.Uid}
	env.service = &userService{
		exec: pe.exec, policy: pe, dashboard: "https://hauswart.example", now: func() time.Time { return monday(16, 0) },
		asked: map[uint32][]time.Time{}, active: map[uint32]int{}, names: map[uint32]knownName{}, recent: map[uint32]recentStatus{},
		send: func(_ context.Context, r api.DeviceRequest) error {
			env.sent = append(env.sent, r)
			return nil
		},
	}
	path := filepath.Join(t.TempDir(), "run", "user.sock")
	listener, err := listenUsers(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o666 {
		t.Fatalf("%v, %v", info, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go env.service.serve(ctx, listener)
	env.client = &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
	}}
	return env
}

func (e *userEnv) post(t *testing.T, body string) (int, string) {
	t.Helper()
	resp, err := e.client.Post("http://agent/request", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data)
}

func (e *userEnv) status(t *testing.T) api.UserStatus {
	t.Helper()
	resp, err := e.client.Get("http://agent/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var out api.UserStatus
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestStatusIsAboutWhoeverAsks(t *testing.T) {
	e := newUserEnv(t)
	got := e.status(t)
	if got.User != e.name || got.Dashboard != "https://hauswart.example" {
		t.Fatalf("got %+v", got)
	}
	if got.ScreenTime == nil || !got.ScreenTime.Allowed || !got.ScreenTime.Until.Equal(monday(19, 0)) {
		t.Fatalf("got %+v", got.ScreenTime)
	}
}

func TestStatusOutsideTheWindow(t *testing.T) {
	e := newUserEnv(t)
	e.service.now = func() time.Time { return monday(20, 0) }
	if got := e.status(t); got.ScreenTime == nil || got.ScreenTime.Allowed {
		t.Fatalf("got %+v", got.ScreenTime)
	}
}

func TestNoRuleMeansNoScreenTime(t *testing.T) {
	e := newUserEnv(t)
	setPolicy(t, e.service.policy, api.Policy{RequiredPackages: []string{"vim"}})
	if got := e.status(t); got.ScreenTime != nil {
		t.Fatalf("got %+v", got.ScreenTime)
	}
}

func TestSharesOfOthersStayOut(t *testing.T) {
	e := newUserEnv(t)
	mounts := e.service.exec.path("/proc/mounts")
	if err := os.MkdirAll(filepath.Dir(mounts), 0o755); err != nil {
		t.Fatal(err)
	}
	text := "//nas/a /media/" + e.name + "-Family cifs rw,uid=" + e.uid + ",gid=1 0 0\n//nas/b /media/other-Secret cifs rw,uid=99999 0 0\n" +
		"//nas/c /media/" + e.name + "-marie-docs cifs rw,uid=99999 0 0\n/dev/x /media/" + e.name + "-Stick ext4 rw 0 0\n"
	if err := os.WriteFile(mounts, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := e.status(t).Shares; !slices.Equal(got, []string{"Family"}) {
		t.Fatalf("got %v", got)
	}
}

func TestDetailsOfThePolicyStayWithAdmins(t *testing.T) {
	e := newUserEnv(t)
	secret := &api.DirectoryRule{URI: "ldaps://a", BaseDN: "dc=a", BindDN: "cn=b", BindPassword: "topsecret", CA: testPEM}
	setPolicy(t, e.service.policy, api.Policy{Directory: secret, Nextcloud: &api.NextcloudRule{URL: "https://cloud.home", Mode: api.NextcloudDrive}})
	resp, err := e.client.Get("http://agent/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(raw), "topsecret") || strings.Contains(string(raw), "ldaps") {
		t.Fatalf("got %s", raw)
	}
	if !strings.Contains(string(raw), "cloud.home") {
		t.Fatalf("got %s", raw)
	}
}

func TestRequestGoesOutUnderTheKernelsName(t *testing.T) {
	e := newUserEnv(t)
	code, body := e.post(t, `{"kind":"software","detail":"vim","reason":"for school"}`)
	if code != http.StatusCreated {
		t.Fatalf("%d %s", code, body)
	}
	if len(e.sent) != 1 || e.sent[0].User != e.name || e.sent[0].Detail != "vim" {
		t.Fatalf("got %+v", e.sent)
	}
}

func TestSocketRefuses(t *testing.T) {
	e := newUserEnv(t)
	for name, body := range map[string]string{
		"claims a user":  `{"kind":"software","detail":"vim","user":"root"}`,
		"unknown kind":   `{"kind":"root","detail":"please"}`,
		"no detail":      `{"kind":"software","detail":""}`,
		"control":        `{"kind":"software","detail":"vim\u001b[2K"}`,
		"not json":       `nonsense`,
		"too long":       `{"kind":"software","detail":"` + strings.Repeat("x", 300) + `"}`,
		"larger than ok": `{"kind":"software","detail":"` + strings.Repeat("x", maxUserBody) + `"}`,
	} {
		if code, data := e.post(t, body); code < 400 {
			t.Errorf("%s: %d %s", name, code, data)
		}
	}
	if len(e.sent) != 0 {
		t.Fatalf("got %+v", e.sent)
	}
}

func TestRequestsAreLimited(t *testing.T) {
	e := newUserEnv(t)
	for range userRequestsMax {
		if code, body := e.post(t, `{"kind":"software","detail":"vim"}`); code != http.StatusCreated {
			t.Fatalf("%d %s", code, body)
		}
	}
	if code, _ := e.post(t, `{"kind":"software","detail":"vim"}`); code != http.StatusTooManyRequests {
		t.Fatalf("got %d", code)
	}
	e.service.now = func() time.Time { return monday(17, 1) }
	if code, _ := e.post(t, `{"kind":"software","detail":"vim"}`); code != http.StatusCreated {
		t.Fatalf("got %d", code)
	}
}

func TestServerAwayIsSaidPlainly(t *testing.T) {
	e := newUserEnv(t)
	e.service.send = func(context.Context, api.DeviceRequest) error { return errors.New("no route") }
	if code, body := e.post(t, `{"kind":"software","detail":"vim"}`); code != http.StatusBadGateway || strings.Contains(body, "route") {
		t.Fatalf("%d %s", code, body)
	}
}

func TestRefusalsSayWhyAndCostNothing(t *testing.T) {
	e := newUserEnv(t)
	e.service.send = func(context.Context, api.DeviceRequest) error { return api.Fail(api.ErrNoSuchUser) }
	for range userRequestsMax + 3 {
		code, body := e.post(t, `{"kind":"software","detail":"vim"}`)
		if code != http.StatusUnprocessableEntity || !strings.Contains(body, api.ErrNoSuchUser) {
			t.Fatalf("%d %s", code, body)
		}
	}
}

// A child in a loop must not reach the processes or files of the agent.
func TestAskingInALoopCostsNothing(t *testing.T) {
	e := newUserEnv(t)
	var lookups atomic.Int64
	base := e.service.exec.Run
	e.service.exec.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		lookups.Add(1)
		return base(ctx, name, args...)
	}
	var wg sync.WaitGroup
	var refused atomic.Int64
	for range 200 {
		wg.Go(func() {
			resp, err := e.client.Get("http://agent/status")
			if err != nil {
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusTooManyRequests {
				refused.Add(1)
			}
		})
	}
	wg.Wait()
	if got := lookups.Load(); got > 20 {
		t.Fatalf("%d commands for 200 questions", got)
	}
}

func TestAtMostSomeRequestsPerPersonAtOnce(t *testing.T) {
	e := newUserEnv(t)
	release := make(chan struct{})
	started := make(chan struct{}, maxUserPerUID)
	e.service.send = func(context.Context, api.DeviceRequest) error {
		started <- struct{}{}
		<-release
		return nil
	}
	var wg sync.WaitGroup
	for range maxUserPerUID {
		wg.Go(func() { e.post(t, `{"kind":"software","detail":"vim"}`) })
	}
	for range maxUserPerUID {
		<-started
	}
	if code, _ := e.post(t, `{"kind":"software","detail":"vim"}`); code != http.StatusTooManyRequests {
		t.Fatalf("got %d", code)
	}
	close(release)
	wg.Wait()
}
