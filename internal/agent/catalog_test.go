package agent

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/catalog"
)

func TestParseCatalog(t *testing.T) {
	for manager, tc := range map[string]struct{ out, want string }{
		"dnf5": {
			"Updating and loading repositories:\nRepositories loaded.\nvim-enhanced\nvim-enhanced\nneovim\n",
			"neovim vim-enhanced",
		},
		"apt":    {"vim\nlibc6\nvim-tiny\n", "libc6 vim vim-tiny"},
		"pacman": {"gvim\nvim\n", "gvim vim"},
		"zypper": {
			"S | Name         | Summary          | Type\n--+--------------+------------------+--------\n  | vim          | Vi IMproved      | package\ni | vim-data     | Data files       | package\n",
			"vim vim-data",
		},
	} {
		got := strings.Join(api.NewCatalog(parseCatalog(tc.out)).Names, " ")
		if got != tc.want {
			t.Errorf("%s: got %q, want %q", manager, got, tc.want)
		}
	}
}

func TestCollectCatalog(t *testing.T) {
	var asked []string
	e := &Executor{
		Platform: Platform{Backend: &Backend{Available: []string{"apt-cache", "pkgnames"}}},
		Run: func(_ context.Context, name string, args ...string) (string, error) {
			asked = append([]string{name}, args...)
			return "vim\nemacs\n", nil
		},
	}
	c, err := e.collectCatalog(context.Background())
	if err != nil || !slices.Equal(c.Names, []string{"emacs", "vim"}) || c.Check() != nil {
		t.Fatalf("%+v %v", c, err)
	}
	if !slices.Equal(asked, []string{"apt-cache", "pkgnames"}) {
		t.Fatalf("ran %v", asked)
	}
	e.Platform.Backend.Available = nil
	if _, err := e.collectCatalog(context.Background()); !errors.Is(err, errNoCatalog) {
		t.Fatalf("got %v", err)
	}
}

// zypper refuses to run twice, so listing waits for a package task to end.
func TestCollectCatalogWaitsForPackageTasks(t *testing.T) {
	ran := make(chan struct{}, 1)
	e := &Executor{
		Platform: Platform{Backend: &Backend{Available: []string{"zypper", "search"}}},
		Run: func(context.Context, string, ...string) (string, error) {
			ran <- struct{}{}
			return "vim\n", nil
		},
	}
	release := e.lockPackages()
	done := make(chan struct{})
	go func() {
		e.collectCatalog(context.Background())
		close(done)
	}()
	select {
	case <-ran:
		t.Fatal("listed while a package task ran")
	case <-time.After(50 * time.Millisecond):
	}
	release()
	<-done
	<-ran
}

func TestEveryBackendWithAListCanSearch(t *testing.T) {
	for _, tool := range []string{"dnf5", "dnf", "apt-get", "zypper", "pacman"} {
		backend := detectBackend(func(name string) bool { return name == tool }, false)
		if backend == nil || len(backend.Available) == 0 {
			t.Errorf("%s: no list of available packages", tool)
		}
	}
}

func TestSearchAtTheSocket(t *testing.T) {
	e := newUserEnv(t)
	var asked []string
	e.service.search = func(_ context.Context, kind, q string) ([]catalog.Entry, error) {
		asked = append(asked, kind+" "+q)
		if q == "fail" {
			return nil, errors.New("server away")
		}
		return []catalog.Entry{{Name: "org.gimp.GIMP", Title: "GIMP"}}, nil
	}
	get := func(query string) (int, string) {
		resp, err := e.client.Get("http://agent/search?" + query)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var b strings.Builder
		buf := make([]byte, 4096)
		n, _ := resp.Body.Read(buf)
		b.Write(buf[:n])
		return resp.StatusCode, b.String()
	}
	if code, body := get("kind=flatpak&q=GIMP"); code != http.StatusOK || !strings.Contains(body, "org.gimp.GIMP") {
		t.Fatalf("%d %s", code, body)
	}
	if code, body := get("kind=flatpak&q=fail"); code != http.StatusOK || strings.TrimSpace(body) != "[]" {
		t.Fatalf("%d %s", code, body)
	}
	if code, _ := get("kind=root&q=gimp"); code != http.StatusBadRequest {
		t.Fatalf("bad kind: %d", code)
	}
	get("kind=package&q=g")
	if !slices.Equal(asked, []string{"flatpak gimp", "flatpak fail"}) {
		t.Fatalf("asked %v", asked)
	}
	for range userSearchesMax {
		get("kind=package&q=vim")
	}
	if len(asked) != userSearchesMax {
		t.Fatalf("no limit: %d searches", len(asked))
	}
}
