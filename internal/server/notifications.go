package server

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"unicode"

	"github.com/philippe/hauswart/internal/notify"
)

const maxShownHostname = 64

// StartNotifications reads the credentials and sends in the background until
// ctx ends. A broken file must not take the household's server down, so it only
// costs the notifications, and the log says why.
func (s *Server) StartNotifications(ctx context.Context, path string) {
	cfg, err := notify.Load(path)
	if err != nil {
		s.log.Error("admin notifications are off", "err", err)
		return
	}
	if !cfg.Enabled() {
		return
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	// Home services often carry a certificate from this CA.
	roots.AddCert(s.ca.Cert)
	s.notifier = notify.New(cfg, roots, s.log)
	s.log.Info("admin notifications are on", "through", strings.Join(cfg.Channels(), ", "))
	go s.notifier.Run(ctx)
}

// notifyRequest tells admins that someone is waiting. The text leaves the house
// when ntfy or mail run elsewhere, so it holds who and where, and neither the
// details nor the free text of the request. It never blocks the request.
func (s *Server) notifyRequest(ctx context.Context, id string) {
	if s.notifier == nil {
		return
	}
	req, err := s.store.GetRequest(ctx, id)
	if err != nil {
		s.log.Error("notification skipped", "err", err)
		return
	}
	s.notifier.Send(fmt.Sprintf("%s asks for %s on %s.\nDecide in the dashboard: %s",
		plainName(req.Username), req.Kind, plainName(req.Hostname), s.publicURL))
}

// plainName keeps only what belongs in a name. A hostname comes from the device
// and is untrusted: it must not add lines or look like a link.
func plainName(s string) string {
	name := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune(".-_", r) {
			return r
		}
		return '_'
	}, s)
	if runes := []rune(name); len(runes) > maxShownHostname {
		return string(runes[:maxShownHostname])
	}
	return name
}
