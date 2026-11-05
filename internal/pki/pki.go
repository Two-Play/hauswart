// Package pki is the small built-in certificate authority. It issues the
// server's TLS certificate and one client certificate per enrolled device.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	caValidity     = 10 * 365 * 24 * time.Hour
	leafValidity   = 2 * 365 * 24 * time.Hour
	caCertFile     = "ca.pem"
	caKeyFile      = "ca-key.pem"
	serverCertFile = "server.pem"
	serverKeyFile  = "server-key.pem"
	renewBefore    = 30 * 24 * time.Hour
	backdateLeeway = time.Hour
)

type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	key     *ecdsa.PrivateKey
	dir     string

	// DeviceValidity overrides the lifetime of device certificates, which
	// makes renewal testable. Zero means the default.
	DeviceValidity time.Duration
}

// LoadOrCreate reads the CA from dir, creating it on first start.
func LoadOrCreate(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, caCertFile))
	if errors.Is(err, os.ErrNotExist) {
		return create(dir)
	}
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, caKeyFile))
	if err != nil {
		return nil, err
	}
	cert, err := ParseCert(certPEM)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("CA key is not PEM")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, CertPEM: certPEM, key: key, dir: dir}, nil
}

func create(dir string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "Hauswart Root CA", Organization: []string{"Hauswart"}},
		NotBefore:             now.Add(-backdateLeeway),
		NotAfter:              now.Add(caValidity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(dir, caKeyFile), keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, caCertFile), certPEM, 0o644); err != nil {
		return nil, err
	}
	return &CA{Cert: cert, CertPEM: certPEM, key: key, dir: dir}, nil
}

// ServerCert returns the stored TLS certificate if it still fits, and issues
// a new one otherwise. Keeping it stable across restarts means a browser
// exception or a pinned certificate survives a service restart.
func (c *CA) ServerCert(hosts []string) (tls.Certificate, error) {
	if pair, ok := c.storedServerCert(hosts); ok {
		return pair, nil
	}
	return c.issueServerCert(hosts)
}

func (c *CA) storedServerCert(hosts []string) (tls.Certificate, bool) {
	pair, err := tls.LoadX509KeyPair(filepath.Join(c.dir, serverCertFile), filepath.Join(c.dir, serverKeyFile))
	if err != nil {
		return tls.Certificate{}, false
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || time.Until(leaf.NotAfter) < renewBefore {
		return tls.Certificate{}, false
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: c.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return tls.Certificate{}, false
	}
	for _, h := range hosts {
		if leaf.VerifyHostname(h) != nil {
			return tls.Certificate{}, false
		}
	}
	return pair, true
}

func (c *CA) issueServerCert(hosts []string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: "hauswart-server"},
		NotBefore:    now.Add(-backdateLeeway),
		NotAfter:     now.Add(leafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, &key.PublicKey, c.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	chainPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), c.CertPEM...)
	if err := os.WriteFile(filepath.Join(c.dir, serverKeyFile), keyPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(filepath.Join(c.dir, serverCertFile), chainPEM, 0o644); err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der, c.Cert.Raw}, PrivateKey: key}, nil
}

// SignDevice turns a CSR into a client certificate whose CN is the device ID.
// Only the public key is taken from the CSR; the subject is set here, so an
// agent cannot choose its own identity.
func (c *CA) SignDevice(csrPEM []byte, deviceID string) (certPEM []byte, serial string, err error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, "", errors.New("CSR is not PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, "", err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, "", fmt.Errorf("CSR signature: %w", err)
	}
	validity := leafValidity
	if c.DeviceValidity > 0 {
		validity = c.DeviceValidity
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: deviceID},
		NotBefore:    now.Add(-min(backdateLeeway, validity/4)),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, csr.PublicKey, c.key)
	if err != nil {
		return nil, "", err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), tmpl.SerialNumber.Text(16), nil
}

// Fingerprint is the hex SHA-256 of the CA certificate. Agents pin it during
// enrollment, which is what makes the first contact trustworthy.
func (c *CA) Fingerprint() string { return Fingerprint(c.Cert.Raw) }

func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func (c *CA) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.Cert)
	return pool
}

func ParseCert(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("not a PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func randomSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		panic(err) // crypto/rand failing is not recoverable
	}
	return n
}
