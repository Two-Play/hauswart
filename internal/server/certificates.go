package server

import (
	"errors"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/pki"
	"github.com/Two-Play/hauswart/internal/store"
)

const (
	maxCertNames    = 20
	defaultCertDays = 365
	maxCertDays     = int(pki.MaxServiceValidity / (24 * time.Hour))
)

func init() {
	addRoutes(func(s *Server, mux *http.ServeMux) {
		mux.Handle("GET /api/certificates", s.admin(s.handleCertificates))
		mux.Handle("POST /api/certificates", s.admin(s.handleIssueCertificate))
	})
}

func (s *Server) handleCertificates(w http.ResponseWriter, r *http.Request, _ store.User) {
	certs, err := s.store.ListServiceCerts(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, certs)
}

// handleIssueCertificate returns a new key exactly once. Only the serial, the
// names and the expiry are kept, so a lost key means issuing a new certificate.
// There is no signature here: the CA key is on this server, so a compromised
// server can issue on its own anyway, within the CA's name constraints.
func (s *Server) handleIssueCertificate(w http.ResponseWriter, r *http.Request, u store.User) {
	var in struct {
		Names []string `json:"names"`
		Days  int      `json:"days"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.Days == 0 {
		in.Days = defaultCertDays
	}
	if in.Days < 1 || in.Days > maxCertDays {
		fail(w, http.StatusBadRequest, api.ErrInvalidCertDays, strconv.Itoa(maxCertDays))
		return
	}
	if len(in.Names) == 0 || len(in.Names) > maxCertNames {
		fail(w, http.StatusBadRequest, api.ErrNoCertNames, strconv.Itoa(maxCertNames))
		return
	}
	names := make([]string, 0, len(in.Names))
	for _, raw := range in.Names {
		name := strings.ToLower(strings.TrimSpace(raw))
		if net.ParseIP(name) == nil && !api.ValidHostName(name) {
			fail(w, http.StatusBadRequest, api.ErrInvalidCertName, raw)
			return
		}
		// Whoever runs that service could otherwise pose as this server to
		// everyone who trusts the CA, and collect dashboard passwords.
		if slices.Contains(s.ownHosts, name) {
			fail(w, http.StatusBadRequest, api.ErrCertServerName, name)
			return
		}
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	cert, err := s.ca.IssueService(names, time.Duration(in.Days)*24*time.Hour)
	var outside *pki.OutsideError
	switch {
	case errors.As(err, &outside):
		fail(w, http.StatusBadRequest, api.ErrCertOutsideCA, outside.Name)
		return
	case errors.Is(err, pki.ErrNotConstrained):
		fail(w, http.StatusConflict, api.ErrCANotConstrained)
		return
	case err != nil:
		s.internal(w, err)
		return
	}
	// Without the record it would be a certificate nobody knows about.
	if err := s.store.AddServiceCert(r.Context(), cert.Serial, names, cert.NotAfter, u.Username); err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, u.Username, "certificate.issued",
		cert.Serial+" "+strings.Join(names, " ")+" until "+cert.NotAfter.UTC().Format(time.RFC3339))
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{
		"serial":    cert.Serial,
		"names":     names,
		"not_after": cert.NotAfter.Unix(),
		"cert":      string(cert.CertPEM),
		"key":       string(cert.KeyPEM),
		"ca":        string(s.ca.CertPEM),
	})
}
