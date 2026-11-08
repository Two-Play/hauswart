// Package catalog finds packages and Flatpaks by part of their name.
package catalog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
)

// FlathubURL is where Flathub answers searches.
const FlathubURL = "https://flathub.org/api/v2/search"

const (
	// MinQuery is the shortest search worth asking for.
	MinQuery = 2
	// MaxQuery keeps what someone types from becoming a request of its own.
	MaxQuery = 64
	// MaxResults is what a search returns at most.
	MaxResults = 20

	flathubTimeout   = 5 * time.Second
	flathubCacheTTL  = time.Hour
	flathubCacheSize = 512
	flathubParallel  = 4
	maxFlathubBody   = 2 << 20
)

// Entry is one search result.
type Entry struct {
	// Name is what goes into a request or a policy: a package name or a
	// Flatpak ID.
	Name string `json:"name"`
	// Title and Summary are for people, and Flathub knows them.
	Title   string `json:"title,omitempty"`
	Summary string `json:"summary,omitempty"`
	// Installed says that a device in question has it already.
	Installed bool `json:"installed,omitempty"`
}

// ErrUnavailable says that Flathub could not answer, so a caller can fall back.
var ErrUnavailable = errors.New("flathub unavailable")

// Flathub searches Flathub. Only the search term leaves the server, never
// anything about devices or people. Answers are cached, so the same letters
// typed again cost nothing, and only a few searches run at once.
type Flathub struct {
	URL    string
	Client *http.Client
	now    func() time.Time

	slots chan struct{}
	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	entries []Entry
	at      time.Time
}

// NewFlathub returns a client for url, normally FlathubURL.
func NewFlathub(url string) *Flathub {
	return &Flathub{
		URL:    url,
		Client: &http.Client{Timeout: flathubTimeout},
		now:    time.Now,
		slots:  make(chan struct{}, flathubParallel),
		cache:  map[string]cached{},
	}
}

// NormalizeQuery trims a search term, and says whether it is worth a search.
func NormalizeQuery(q string) (string, bool) {
	q = strings.ToLower(strings.TrimSpace(q))
	if len(q) < MinQuery || len(q) > MaxQuery || !api.ValidText(q, MaxQuery) {
		return "", false
	}
	return q, true
}

// Search returns the applications on Flathub that match q.
func (f *Flathub) Search(ctx context.Context, q string) ([]Entry, error) {
	q, ok := NormalizeQuery(q)
	if !ok {
		return []Entry{}, nil
	}
	if entries, ok := f.lookup(q); ok {
		return entries, nil
	}
	select {
	case f.slots <- struct{}{}:
		defer func() { <-f.slots }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	entries, err := f.ask(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	f.store(q, entries)
	return entries, nil
}

func (f *Flathub) lookup(q string) ([]Entry, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	hit, ok := f.cache[q]
	if !ok || f.now().Sub(hit.at) > flathubCacheTTL {
		return nil, false
	}
	return hit.entries, true
}

func (f *Flathub) store(q string, entries []Entry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.cache) >= flathubCacheSize {
		// Dropping everything is crude, but it keeps the size fixed without any
		// bookkeeping, and a cache this small fills again in seconds.
		clear(f.cache)
	}
	f.cache[q] = cached{entries: entries, at: f.now()}
}

func (f *Flathub) ask(ctx context.Context, q string) ([]Entry, error) {
	body, err := json.Marshal(map[string]any{"query": q, "hits_per_page": MaxResults})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "hauswart")
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var answer struct {
		Hits []struct {
			AppID   string `json:"app_id"`
			Name    string `json:"name"`
			Summary string `json:"summary"`
		} `json:"hits"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxFlathubBody)).Decode(&answer); err != nil {
		return nil, err
	}
	entries := []Entry{}
	for _, hit := range answer.Hits {
		// What comes back ends up in a dashboard and a request, so it has to be
		// what Hauswart would accept from a person as well.
		if !api.ValidPackage(hit.AppID) || !api.ValidAppID(hit.AppID) {
			continue
		}
		entries = append(entries, Entry{Name: hit.AppID, Title: shortText(hit.Name), Summary: shortText(hit.Summary)})
		if len(entries) == MaxResults {
			break
		}
	}
	return entries, nil
}

func shortText(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 160 {
		s = s[:160]
		for !api.ValidText(s, 160) && len(s) > 0 {
			s = s[:len(s)-1]
		}
	}
	if !api.ValidText(s, 160) {
		return ""
	}
	return s
}
