package agent

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/go-attestation/attest"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/pki"
)

// keyTPMFile holds the TLS key that lives in the TPM. Only this TPM can use
// it, so a copy of the agent's files is of no use on another computer.
const keyTPMFile = "agent-key.tpm"

// tpmSigner signs with a key in the TPM. A TPM does one thing at a time, and
// TLS handshakes can come at once.
type tpmSigner struct {
	mu     sync.Mutex
	signer crypto.Signer
	// tpm stays open for as long as the agent runs.
	tpm *attest.TPM
	key *attest.Key
}

func (s *tpmSigner) Public() crypto.PublicKey { return s.signer.Public() }

func (s *tpmSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.signer.Sign(r, digest, opts)
}

func (s *tpmSigner) Close() {
	s.key.Close()
	s.tpm.Close()
}

// loadTPMKey opens a key the TPM made before.
func loadTPMKey(blob []byte) (*tpmSigner, error) {
	tpm, err := openTPM()
	if err != nil {
		return nil, err
	}
	key, err := tpm.LoadKey(blob)
	if err != nil {
		tpm.Close()
		return nil, err
	}
	private, err := key.Private(key.Public())
	if err != nil {
		key.Close()
		tpm.Close()
		return nil, err
	}
	signer, ok := private.(crypto.Signer)
	if !ok {
		key.Close()
		tpm.Close()
		return nil, errors.New("the TPM key cannot sign")
	}
	return &tpmSigner{signer: signer, tpm: tpm, key: key}, nil
}

func samePublicKey(a, b crypto.PublicKey) bool {
	x, err1 := x509.MarshalPKIXPublicKey(a)
	y, err2 := x509.MarshalPKIXPublicKey(b)
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}

// loadIdentity reads the certificate and its key: the one in the TPM if the
// certificate is for it, otherwise the key file. A move into the TPM that
// stopped half way leaves the certificate of the file key, which still works.
func loadIdentity(dir string) (tls.Certificate, *x509.Certificate, bool, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, certFile))
	if err != nil {
		return tls.Certificate{}, nil, false, err
	}
	leaf, err := pki.ParseCert(certPEM)
	if err != nil {
		return tls.Certificate{}, nil, false, err
	}
	if blob, err := os.ReadFile(filepath.Join(dir, keyTPMFile)); err == nil {
		signer, err := loadTPMKey(blob)
		if err == nil && samePublicKey(signer.Public(), leaf.PublicKey) {
			return tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: signer, Leaf: leaf}, leaf, true, nil
		}
		if err == nil {
			signer.Close()
		} else if _, statErr := os.Stat(filepath.Join(dir, keyFile)); statErr != nil {
			// The certificate is for the TPM key, and the TPM does not have
			// it any more: the device has to be enrolled again.
			return tls.Certificate{}, nil, false, fmt.Errorf("the TLS key in the TPM is gone (%w); enroll this device again", err)
		}
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, certFile), filepath.Join(dir, keyFile))
	if err != nil {
		return tls.Certificate{}, nil, false, err
	}
	return cert, leaf, false, nil
}

// CertifiedKey makes a TLS key in the TPM, has the attestation key certify it
// and asks the server for a certificate. It returns the key's blob, the
// certificate and the key itself.
func (at *Attestor) CertifiedKey(ctx context.Context, tpm *attest.TPM) ([]byte, string, crypto.PublicKey, error) {
	ak, _, err := at.attestationKey(ctx, tpm)
	if err != nil {
		return nil, "", nil, err
	}
	defer ak.Close(tpm)
	key, err := tpm.NewKey(ak, &attest.KeyConfig{Algorithm: attest.ECDSA, Size: 256})
	if err != nil {
		return nil, "", nil, err
	}
	defer key.Close()
	private, err := key.Private(key.Public())
	if err != nil {
		return nil, "", nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "hauswart-agent"}}, private)
	if err != nil {
		return nil, "", nil, err
	}
	params := key.CertificationParameters()
	var out api.RenewResponse
	err = at.exchange(ctx, "/agent/tpm/rekey", api.TPMRekey{
		CSR:    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})),
		Public: params.Public, CreateData: params.CreateData,
		CreateAttestation: params.CreateAttestation, CreateSignature: params.CreateSignature,
	}, &out)
	if err != nil {
		return nil, "", nil, err
	}
	blob, err := key.Marshal()
	if err != nil {
		return nil, "", nil, err
	}
	return blob, out.Cert, key.Public(), nil
}

// moveKeyToTPM replaces the key file with a key in the TPM, keeping the
// device's ID. The key file goes only once the server took the new
// certificate, so a failure on the way leaves a device that still connects.
func (a *Agent) moveKeyToTPM(ctx context.Context, tpm *attest.TPM) error {
	at := &Attestor{Client: a.client, Server: a.cfg.Server, Dir: a.dir}
	blob, certPEM, public, err := at.CertifiedKey(ctx, tpm)
	if err != nil {
		return err
	}
	leaf, err := pki.ParseCert([]byte(certPEM))
	if err != nil {
		return err
	}
	opts := x509.VerifyOptions{Roots: a.pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if _, err := leaf.Verify(opts); err != nil {
		return fmt.Errorf("certificate for the TPM key: %w", err)
	}
	if leaf.Subject.CommonName != a.cfg.DeviceID || !samePublicKey(leaf.PublicKey, public) {
		return errors.New("the certificate for the TPM key is for another device or key")
	}
	if err := writeAtomicSync(filepath.Join(a.dir, keyTPMFile), blob, 0o600); err != nil {
		return err
	}
	signer, err := loadTPMKey(blob)
	if err != nil {
		return err
	}
	if err := writeAtomicSync(filepath.Join(a.dir, certFile), []byte(certPEM), 0o600); err != nil {
		signer.Close()
		return err
	}
	a.mu.Lock()
	previous := a.cert.PrivateKey
	a.cert = tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: signer, Leaf: leaf}
	a.leaf = leaf
	a.keyInTPM = true
	a.mu.Unlock()
	if old, ok := previous.(*tpmSigner); ok {
		old.Close()
	}
	a.client.CloseIdleConnections()
	// The first request with the new certificate makes the server drop the
	// old one; only then can the key file go.
	if err := at.exchange(ctx, "/agent/tpm/nonce", struct{}{}, nil); err != nil {
		return fmt.Errorf("the server did not take the certificate of the TPM key: %w", err)
	}
	if err := os.Remove(filepath.Join(a.dir, keyFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	a.log.Info("the TLS key moved into the TPM", "expires", leaf.NotAfter)
	return nil
}

// wantsTPMKey says whether the device owner left the key move on.
func (c Config) wantsTPMKey() bool { return c.TPMKey == nil || *c.TPMKey }
