package server

import (
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// The server is meant for the local network. Whether the internet reaches it
// cannot be told without asking a service outside, which would learn about
// this server, so it looks at what it can see itself: the addresses it listens
// on, and the addresses requests come from.

// Exposure is what makes the server look reachable from outside.
type Exposure struct {
	// Reason is "listening" for a public address of its own, "reached" for a
	// request from one.
	Reason  string    `json:"reason"`
	Address string    `json:"address"`
	At      time.Time `json:"at"`
}

type exposureWatch struct {
	mu        sync.Mutex
	allowed   bool
	listening *Exposure
	reached   *Exposure
}

// cgnat is the shared address space, which VPNs such as Tailscale use for
// addresses that are not on the internet.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// publicAddress says whether an address is on the internet.
func publicAddress(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsValid() && a.IsGlobalUnicast() && !a.IsPrivate() && !cgnat.Contains(a)
}

// AllowPublic turns the warning off, for a server that is meant to have public
// addresses, such as one behind a VPN that hands them out.
func (s *Server) AllowPublic(allowed bool) {
	s.exposure.mu.Lock()
	defer s.exposure.mu.Unlock()
	s.exposure.allowed = allowed
}

// CheckListen looks at the address the server listens on. One that listens on
// every interface counts as public if any interface has a public address.
func (s *Server) CheckListen(addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return
	}
	var candidates []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil && !ip.IsUnspecified() {
		candidates = []netip.Addr{ip}
	} else if host == "" || err == nil {
		addrs, _ := net.InterfaceAddrs()
		for _, a := range addrs {
			if prefix, err := netip.ParsePrefix(a.String()); err == nil {
				candidates = append(candidates, prefix.Addr())
			}
		}
	}
	for _, ip := range candidates {
		if publicAddress(ip) {
			s.exposure.mu.Lock()
			s.exposure.listening = &Exposure{Reason: "listening", Address: ip.String(), At: time.Now()}
			s.exposure.mu.Unlock()
			s.log.Warn("the server listens on a public address and may be reachable from the internet", "address", ip)
			return
		}
	}
}

// seen notes a request from a public address. Only the last one is kept.
func (s *Server) seen(r *http.Request) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil || !publicAddress(ap.Addr()) {
		return
	}
	s.exposure.mu.Lock()
	first := s.exposure.reached == nil
	s.exposure.reached = &Exposure{Reason: "reached", Address: ap.Addr().Unmap().String(), At: time.Now()}
	s.exposure.mu.Unlock()
	if first {
		s.log.Warn("a request came from a public address, the server is reachable from outside", "address", ap.Addr())
	}
}

// currentExposure is what the dashboard warns about, nil for nothing.
func (s *Server) currentExposure() *Exposure {
	s.exposure.mu.Lock()
	defer s.exposure.mu.Unlock()
	if s.exposure.allowed {
		return nil
	}
	if s.exposure.reached != nil {
		e := *s.exposure.reached
		return &e
	}
	if s.exposure.listening != nil {
		e := *s.exposure.listening
		return &e
	}
	return nil
}
