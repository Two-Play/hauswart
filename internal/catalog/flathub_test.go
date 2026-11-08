package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func fakeFlathub(t *testing.T, status int, calls *atomic.Int64) *Flathub {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var in struct{ Query string }
		json.NewDecoder(r.Body).Decode(&in)
		if in.Query != "gimp" {
			t.Errorf("query %q", in.Query)
		}
		w.WriteHeader(status)
		w.Write([]byte(`{"hits":[
			{"app_id":"org.gimp.GIMP","name":"GNU Image\nManipulation Program","summary":"High-end image creation"},
			{"app_id":"--evil","name":"x"},
			{"app_id":"com.github._4lex4.ScanTailor-Advanced","name":"ScanTailor"}]}`))
	}))
	t.Cleanup(srv.Close)
	return NewFlathub(srv.URL)
}

func TestFlathubSearch(t *testing.T) {
	var calls atomic.Int64
	f := fakeFlathub(t, http.StatusOK, &calls)
	entries, err := f.Search(context.Background(), "  GIMP ")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0] != (Entry{Name: "org.gimp.GIMP", Title: "GNU Image Manipulation Program", Summary: "High-end image creation"}) ||
		entries[1].Name != "com.github._4lex4.ScanTailor-Advanced" {
		t.Fatalf("got %+v", entries)
	}
	if _, err := f.Search(context.Background(), "gimp"); err != nil || calls.Load() != 1 {
		t.Fatalf("not cached: %v %d", err, calls.Load())
	}
	f.now = func() time.Time { return time.Now().Add(2 * flathubCacheTTL) }
	f.Search(context.Background(), "gimp")
	if calls.Load() != 2 {
		t.Fatalf("cache never expires: %d", calls.Load())
	}
}

func TestFlathubShortQueryAsksNobody(t *testing.T) {
	var calls atomic.Int64
	f := fakeFlathub(t, http.StatusOK, &calls)
	for _, q := range []string{"", "g", " x ", string(make([]byte, MaxQuery+1)), "a\x00b"} {
		if entries, err := f.Search(context.Background(), q); err != nil || len(entries) != 0 {
			t.Errorf("%q: %v %v", q, entries, err)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("asked %d times", calls.Load())
	}
}

func TestFlathubFailureIsUnavailable(t *testing.T) {
	var calls atomic.Int64
	f := fakeFlathub(t, http.StatusBadGateway, &calls)
	if _, err := f.Search(context.Background(), "gimp"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
	f.Search(context.Background(), "gimp")
	if calls.Load() != 2 {
		t.Fatalf("a failure was cached: %d", calls.Load())
	}
}
