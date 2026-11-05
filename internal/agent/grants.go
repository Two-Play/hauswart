package agent

import (
	"encoding/json"
	"errors"
	"maps"
	"os"
	"sync"
	"time"
)

// GrantStore remembers when each sudo grant ends. It is persisted because
// sudoers has no expiry of its own and a reboot must not extend a grant.
type GrantStore struct {
	path string
	mu   sync.Mutex
	data map[string]time.Time
}

func OpenGrants(path string) (*GrantStore, error) {
	g := &GrantStore{path: path, data: map[string]time.Time{}}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return g, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &g.data); err != nil {
		return nil, err
	}
	return g, nil
}

func (g *GrantStore) Set(user string, expires time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.data[user] = expires
	return g.save()
}

func (g *GrantStore) Delete(user string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.data, user)
	return g.save()
}

func (g *GrantStore) Expired(now time.Time) []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	var users []string
	for user, expires := range g.data {
		if !now.Before(expires) {
			users = append(users, user)
		}
	}
	return users
}

func (g *GrantStore) save() error {
	raw, err := json.Marshal(g.data)
	if err != nil {
		return err
	}
	return writeAtomic(g.path, raw, 0o600)
}

// All returns a copy of the running grants.
func (g *GrantStore) All() map[string]time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	return maps.Clone(g.data)
}
