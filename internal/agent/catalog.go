package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/catalog"
)

const (
	// The names of all packages change with the repositories, slowly.
	catalogInterval = 24 * time.Hour
	catalogRetry    = time.Hour
	// A first metadata download can take a while on a slow line.
	catalogTimeout = 10 * time.Minute
	// catalogDelay keeps the start of the agent free for what matters more.
	catalogDelay      = 2 * time.Minute
	maxSearchResponse = 64 << 10
)

// parseCatalog reads one package name per line, or the second column of a
// zypper table. NewCatalog drops what is not a name, such as progress lines.
func parseCatalog(out string) []string {
	var names []string
	for line := range strings.Lines(out) {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "|") {
			fields := strings.Split(line, "|")
			if len(fields) < 2 {
				continue
			}
			name := strings.TrimSpace(fields[1])
			if name == "Name" {
				continue // the header
			}
			names = append(names, name)
			continue
		}
		names = append(names, line)
	}
	return names
}

// collectCatalog lists what the package manager could install.
func (e *Executor) collectCatalog(ctx context.Context) (api.PackageCatalog, error) {
	backend := e.Platform.Backend
	if backend == nil || backend.Available == nil {
		return api.PackageCatalog{}, errNoCatalog
	}
	ctx, cancel := context.WithTimeout(ctx, catalogTimeout)
	defer cancel()
	out, err := e.Run(ctx, backend.Available[0], backend.Available[1:]...)
	if err != nil {
		return api.PackageCatalog{}, err
	}
	c := api.NewCatalog(parseCatalog(out))
	if len(c.Names) == 0 {
		return c, errors.New("the package manager lists no packages")
	}
	return c, nil
}

var errNoCatalog = errors.New("this package manager cannot list what is available")

// sendCatalog tells the server which catalog the device has, and sends it only
// if the server does not know it yet.
func (a *Agent) sendCatalog(ctx context.Context, c api.PackageCatalog) error {
	err := a.post(ctx, "/agent/catalog/link", map[string]string{"hash": c.Hash})
	if err == nil {
		return nil
	}
	if !strings.Contains(err.Error(), "status 404") {
		return err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(c); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.Server+"/agent/catalog", &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

func (a *Agent) catalogLoop(ctx context.Context) {
	next := time.Now().Add(catalogDelay)
	last := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(next)):
		}
		next = time.Now().Add(catalogInterval)
		c, err := a.exec.collectCatalog(ctx)
		if errors.Is(err, errNoCatalog) {
			return
		}
		if err == nil && c.Hash != last {
			err = a.sendCatalog(ctx, c)
		}
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				a.log.Warn("sending the package catalog failed", "err", err)
			}
			next = time.Now().Add(catalogRetry)
			continue
		}
		last = c.Hash
	}
}

// search asks the server, which knows this device's catalog and Flathub.
func (a *Agent) search(ctx context.Context, kind, q string) ([]catalog.Entry, error) {
	query := url.Values{"kind": {kind}, "q": {q}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.Server+"/agent/catalog/search?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var entries []catalog.Entry
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxSearchResponse)).Decode(&entries); err != nil {
		return nil, err
	}
	if len(entries) > catalog.MaxResults {
		entries = entries[:catalog.MaxResults]
	}
	return entries, nil
}
