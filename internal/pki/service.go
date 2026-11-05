package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// MaxServiceValidity stays below the 398 days that browsers accept.
const MaxServiceValidity = 397 * 24 * time.Hour

// ErrNotConstrained reports a CA without name constraints. Every device trusts
// this CA, so without a limit it could issue a certificate for any website.
var ErrNotConstrained = errors.New("CA has no name constraints")

// OutsideError reports a name the CA must not issue for.
type OutsideError struct{ Name string }

func (e *OutsideError) Error() string { return e.Name + " is outside the CA's permitted names" }

// ServiceCert is a certificate for a home service. KeyPEM exists only here:
// the caller hands it out and must not keep it.
type ServiceCert struct {
	CertPEM  []byte
	KeyPEM   []byte
	Serial   string
	NotAfter time.Time
}

// constrained says whether the CA carries a usable limit. Older CAs have none.
func (c *CA) constrained() bool {
	return c.Cert.PermittedDNSDomainsCritical &&
		(len(c.Cert.PermittedDNSDomains) > 0 || len(c.Cert.PermittedIPRanges) > 0)
}

// permits checks a name against the constraints, leaving out the entries that
// only fill an otherwise empty list.
func (c *CA) permits(name string) bool {
	if ip := net.ParseIP(name); ip != nil {
		for _, ipNet := range c.Cert.PermittedIPRanges {
			if ipNet.Contains(ip) && !ip.Equal(placeholderIP) {
				return true
			}
		}
		return false
	}
	for _, entry := range c.Cert.PermittedDNSDomains {
		domain := strings.ToLower(entry)
		if domain != placeholderDomain && (name == domain || strings.HasSuffix(name, "."+strings.TrimPrefix(domain, "."))) {
			return true
		}
	}
	return false
}

// IssueService creates a key and a server certificate for names, which may be
// DNS names or IP addresses. The certificate cannot act as a device, because it
// is only good for serving TLS, and it cannot sign anything.
func (c *CA) IssueService(names []string, validity time.Duration) (ServiceCert, error) {
	if !c.constrained() {
		return ServiceCert{}, ErrNotConstrained
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return ServiceCert{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: names[0]},
		NotBefore:             now.Add(-backdateLeeway),
		NotAfter:              now.Add(min(validity, MaxServiceValidity)),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, name := range names {
		if !c.permits(name) {
			return ServiceCert{}, &OutsideError{Name: name}
		}
		if ip := net.ParseIP(name); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, name)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, &key.PublicKey, c.key)
	if err != nil {
		return ServiceCert{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return ServiceCert{}, err
	}
	// The same check a client makes, so that no difference between it and
	// permits can let a certificate out.
	opts := x509.VerifyOptions{Roots: c.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if _, err := leaf.Verify(opts); err != nil {
		return ServiceCert{}, fmt.Errorf("service certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return ServiceCert{}, err
	}
	return ServiceCert{
		CertPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		Serial:   tmpl.SerialNumber.Text(16),
		NotAfter: leaf.NotAfter,
	}, nil
}
