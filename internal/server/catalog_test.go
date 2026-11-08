package server

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/catalog"
	"github.com/Two-Play/hauswart/internal/store"
)

// sendCatalog posts a gzipped catalog, as the agent does.
func (e *env) sendCatalog(agent *http.Client, c api.PackageCatalog) int {
	e.t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	json.NewEncoder(zw).Encode(c)
	zw.Close()
	req, _ := http.NewRequest("POST", e.ts.URL+"/agent/catalog", &buf)
	req.Header.Set("X-Hauswart", "1")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := agent.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func search(t *testing.T, e *env, c *http.Client, query string) (int, []catalog.Entry) {
	t.Helper()
	code, data := e.do(c, "GET", "/api/catalog/search?"+query, nil)
	var entries []catalog.Entry
	json.Unmarshal(data, &entries)
	return code, entries
}

func names(entries []catalog.Entry) string {
	var out []string
	for _, entry := range entries {
		out = append(out, entry.Name)
	}
	return strings.Join(out, " ")
}

func TestCatalogUploadAndSearch(t *testing.T) {
	e := setup(t)
	id, agent := e.enroll()
	other, otherAgent := e.enroll()
	list := api.NewCatalog([]string{"vim", "vim-enhanced", "neovim", "emacs"})

	if code, _ := e.do(agent, "POST", "/agent/catalog/link", map[string]string{"hash": list.Hash}); code != http.StatusNotFound {
		t.Fatalf("unknown catalog linked: %d", code)
	}
	if code := e.sendCatalog(agent, list); code != http.StatusNoContent {
		t.Fatalf("upload: %d", code)
	}
	if code, _ := e.do(otherAgent, "POST", "/agent/catalog/link", map[string]string{"hash": list.Hash}); code != http.StatusNoContent {
		t.Fatalf("link: %d", code)
	}
	forged := list
	forged.Names = []string{"evil"}
	if code := e.sendCatalog(agent, forged); code != http.StatusBadRequest {
		t.Fatalf("names under a foreign hash: %d", code)
	}

	admin := e.login("admin")
	if code, entries := search(t, e, admin, "kind=package&q=vim"); code != http.StatusOK || names(entries) != "vim vim-enhanced neovim" {
		t.Fatalf("%d %v", code, entries)
	}
	if _, entries := search(t, e, admin, "kind=package&q=v"); len(entries) != 0 {
		t.Fatalf("one letter: %v", entries)
	}
	if code, _ := search(t, e, admin, "kind=root&q=vim"); code != http.StatusBadRequest {
		t.Fatalf("bad kind: %d", code)
	}

	// A member searches only on a device assigned to them.
	e.assign("anna", id)
	anna := e.login("anna")
	if code, entries := search(t, e, anna, "kind=package&q=emac&device="+id); code != http.StatusOK || names(entries) != "emacs" {
		t.Fatalf("%d %v", code, entries)
	}
	for _, query := range []string{"kind=package&q=vim&device=" + other, "kind=package&q=vim", "kind=package&q=vim&group=1"} {
		if code, _ := search(t, e, anna, query); code != http.StatusForbidden {
			t.Errorf("%s: %d", query, code)
		}
	}

	// A device searches with itself in scope.
	code, data := e.do(agent, "GET", "/agent/catalog/search?kind=package&q=neo", nil)
	if code != http.StatusOK || !strings.Contains(string(data), "neovim") {
		t.Fatalf("%d %s", code, data)
	}
}

func TestFlatpakSearchAsksFlathub(t *testing.T) {
	e := setup(t)
	id, agent := e.enroll()
	if code, _ := e.do(agent, "POST", "/agent/inventory", api.Inventory{Packages: []api.Package{
		{Kind: api.PackageFlatpak, Name: "org.kde.kate", Version: "24"},
	}}); code != http.StatusNoContent {
		t.Fatalf("inventory: %d", code)
	}
	admin := e.login("admin")

	// Without Flathub, only installed Flatpaks are found.
	if _, entries := search(t, e, admin, "kind=flatpak&q=kate"); names(entries) != "org.kde.kate" || !entries[0].Installed {
		t.Fatalf("got %+v", entries)
	}

	up := true
	flathub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		io.Copy(io.Discard, r.Body)
		w.Write([]byte(`{"hits":[{"app_id":"org.kde.kate","name":"Kate","summary":"Text editor"},{"app_id":"org.kde.kwrite","name":"KWrite"}]}`))
	}))
	t.Cleanup(flathub.Close)
	e.server.SetFlathub(catalog.NewFlathub(flathub.URL))

	_, entries := search(t, e, admin, "kind=flatpak&q=kate&device="+id)
	if names(entries) != "org.kde.kate org.kde.kwrite" || !entries[0].Installed || entries[1].Installed || entries[0].Title != "Kate" {
		t.Fatalf("got %+v", entries)
	}
	up = false
	if _, entries := search(t, e, admin, "kind=flatpak&q=kwr"); len(entries) != 0 {
		t.Fatalf("got %+v", entries)
	}
	if code, entries := search(t, e, admin, "kind=flatpak&q=kat"); code != http.StatusOK || names(entries) != "org.kde.kate" {
		t.Fatalf("no fallback: %d %+v", code, entries)
	}
}

func TestApproverSearchesEverywhereButNotByGroup(t *testing.T) {
	e := setup(t)
	e.enroll()
	e.addUser("mia", "mia", store.RoleApprover)
	mia := e.login("mia")
	if code, _ := search(t, e, mia, "kind=package&q=vim"); code != http.StatusOK {
		t.Fatalf("all devices: %d", code)
	}
	if code, _ := search(t, e, mia, "kind=package&q=vim&group=1"); code != http.StatusForbidden {
		t.Fatalf("group: %d", code)
	}
}
