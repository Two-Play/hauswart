package server

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/catalog"
	"github.com/Two-Play/hauswart/internal/store"
)

func init() {
	addRoutes(func(s *Server, mux *http.ServeMux) {
		mux.Handle("GET /api/catalog/search", s.user(s.handleSearch))
		mux.Handle("POST /agent/catalog/link", s.agent(s.handleCatalogLink))
		mux.Handle("POST /agent/catalog", s.agent(s.handleCatalog))
		mux.Handle("GET /agent/catalog/search", s.agent(s.handleDeviceSearch))
	})
}

// SetFlathub lets Flatpak searches ask Flathub. Without it, they only find
// what devices have installed.
func (s *Server) SetFlathub(f *catalog.Flathub) { s.flathub = f }

// handleCatalogLink lets a device skip sending a catalog the server has.
func (s *Server) handleCatalogLink(w http.ResponseWriter, r *http.Request, device string) {
	var in struct {
		Hash string `json:"hash"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	ok, err := s.store.LinkCatalog(r.Context(), device, in.Hash)
	if err != nil {
		s.internal(w, err)
		return
	}
	if !ok {
		fail(w, http.StatusNotFound, api.ErrUnknownCatalog)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleCatalog takes the package names a device could install, gzipped.
func (s *Server) handleCatalog(w http.ResponseWriter, r *http.Request, device string) {
	body := io.Reader(r.Body)
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			fail(w, http.StatusBadRequest, api.ErrInvalidCatalog, "gzip")
			return
		}
		defer zr.Close()
		body = zr
	}
	var in api.PackageCatalog
	// One byte more than allowed tells a large catalog from one that fits.
	limited := &io.LimitedReader{R: body, N: api.MaxCatalogBytes + 1}
	if err := json.NewDecoder(limited).Decode(&in); err != nil || limited.N == 0 {
		fail(w, http.StatusBadRequest, api.ErrInvalidCatalog, "size")
		return
	}
	if err := in.Check(); err != nil {
		failErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.store.SaveCatalog(r.Context(), device, in); err != nil {
		s.internal(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleSearch finds packages or Flatpaks for the dashboard. Members search
// only for a device assigned to them, and the group of a policy is for admins.
func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request, u store.User) {
	query := r.URL.Query()
	kind := query.Get("kind")
	if kind != api.SearchPackage && kind != api.SearchFlatpak {
		fail(w, http.StatusBadRequest, api.ErrInvalidSearch, kind)
		return
	}
	var scope store.Scope
	switch device, group := query.Get("device"), query.Get("group"); {
	case device != "":
		allowed, err := s.store.DeviceAllowed(r.Context(), u.ID, device)
		if err != nil {
			s.internal(w, err)
			return
		}
		if !allowed {
			fail(w, http.StatusForbidden, api.ErrDeviceNotAssigned)
			return
		}
		scope.Devices = []string{device}
	case group != "":
		if u.Role != store.RoleAdmin {
			fail(w, http.StatusForbidden, api.ErrAdminOnly)
			return
		}
		id, err := strconv.ParseInt(group, 10, 64)
		if err != nil {
			fail(w, http.StatusNotFound, api.ErrNoSuchGroup)
			return
		}
		if scope.Devices, err = s.store.GroupDevices(r.Context(), id); err != nil {
			s.internal(w, err)
			return
		}
	case u.Role == store.RoleMember:
		fail(w, http.StatusForbidden, api.ErrDeviceNotAssigned)
		return
	default:
		scope.All = true
	}
	entries, err := s.search(r.Context(), scope, kind, query.Get("q"))
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

// handleDeviceSearch is for the desktop app, through the agent. A device
// searches only with itself in scope.
func (s *Server) handleDeviceSearch(w http.ResponseWriter, r *http.Request, device string) {
	kind := r.URL.Query().Get("kind")
	if kind != api.SearchPackage && kind != api.SearchFlatpak {
		fail(w, http.StatusBadRequest, api.ErrInvalidSearch, kind)
		return
	}
	entries, err := s.search(r.Context(), store.Scope{Devices: []string{device}}, kind, r.URL.Query().Get("q"))
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

// search looks in the catalogs of the devices in scope for packages, and on
// Flathub for Flatpaks. When Flathub is off or away, it falls back to what the
// devices have installed, which beats finding nothing.
func (s *Server) search(ctx context.Context, scope store.Scope, kind, q string) ([]catalog.Entry, error) {
	q, ok := catalog.NormalizeQuery(q)
	if !ok {
		return []catalog.Entry{}, nil
	}
	if kind == api.SearchFlatpak && s.flathub != nil {
		entries, err := s.flathub.Search(ctx, q)
		if err == nil {
			names := make([]string, len(entries))
			for i, entry := range entries {
				names[i] = entry.Name
			}
			installed, err := s.store.InstalledAmong(ctx, scope, api.PackageFlatpak, names)
			if err != nil {
				return nil, err
			}
			for i := range entries {
				entries[i].Installed = installed[entries[i].Name]
			}
			return entries, nil
		}
		if !errors.Is(err, catalog.ErrUnavailable) {
			return nil, err
		}
		s.log.Warn("Flathub search failed, using installed Flatpaks", "err", err)
	}
	hits, err := s.store.SearchPackages(ctx, scope, kind, q, catalog.MaxResults)
	if err != nil {
		return nil, err
	}
	entries := make([]catalog.Entry, len(hits))
	for i, hit := range hits {
		entries[i] = catalog.Entry{Name: hit.Name, Installed: hit.Installed}
	}
	return entries, nil
}
