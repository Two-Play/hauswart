package agent

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/google/go-attestation/attest"

	"github.com/Two-Play/hauswart/internal/api"
)

const (
	// akFile holds the attestation key, which only this TPM can use.
	akFile = "agent-ak.json"
	// attestInterval is how often the device proves its boot. A boot only
	// changes at a restart, so this catches devices that rarely restart.
	attestInterval = 6 * time.Hour
	// attestRetry is the wait after a failure that may go away.
	attestRetry = time.Hour
	// noTPMRetry is the wait on a device without a TPM, which may get one
	// switched on in the firmware.
	noTPMRetry     = 24 * time.Hour
	maxTPMResponse = 64 << 10
)

// openTPM opens the TPM of the device. Tests replace it with a simulator.
var openTPM = func() (*attest.TPM, error) { return attest.OpenTPM(nil) }

// errTPMUnknown says that the server does not trust this attestation key.
var errTPMUnknown = errors.New("the server does not know this attestation key")

type storedAK struct {
	Blob   []byte `json:"blob"`
	Public []byte `json:"public"`
}

// attestLoop proves the boot of the device now and then, from its start on.
func (a *Agent) attestLoop(ctx context.Context) {
	for {
		wait := a.attestOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// attestOnce registers the TPM if it is not yet, and sends a quote. It
// returns how long to wait for the next one.
func (a *Agent) attestOnce(ctx context.Context) time.Duration {
	tpm, err := openTPM()
	if errors.Is(err, attest.ErrTPMNotAvailable) {
		return noTPMRetry
	}
	if err != nil {
		a.log.Warn("opening the TPM failed", "err", err)
		return attestRetry
	}
	defer tpm.Close()
	at := &Attestor{Client: a.client, Server: a.cfg.Server, Dir: a.dir}
	err = at.Prove(ctx, tpm)
	if errors.Is(err, errTPMUnknown) {
		a.log.Warn("the server does not trust the attestation key, registering again later")
		return attestInterval
	}
	if errors.Is(err, os.ErrNotExist) {
		// The firmware measured nothing, which does not change before a
		// restart with other settings.
		a.log.Info("the firmware keeps no measured boot log, so the boot cannot be proven")
		return noTPMRetry
	}
	if err != nil {
		a.log.Warn("proving the boot failed", "err", err)
		return attestRetry
	}
	return attestInterval
}

// Attestor proves the boot of a device to the server.
type Attestor struct {
	Client *http.Client
	Server string
	// Dir holds the attestation key.
	Dir string
	// EventLog replaces the firmware's, for tests.
	EventLog []byte
}

// Prove registers the TPM if the server does not trust it yet, and sends a
// quote of the current boot.
func (at *Attestor) Prove(ctx context.Context, tpm *attest.TPM) error {
	ak, public, err := at.attestationKey(ctx, tpm)
	if err != nil {
		return fmt.Errorf("registering the TPM: %w", err)
	}
	defer ak.Close(tpm)
	err = at.sendQuote(ctx, tpm, ak, public)
	if errors.Is(err, errTPMUnknown) {
		// The server lost the key, or waits for an admin to accept another
		// TPM. A new key registers the next time.
		os.Remove(filepath.Join(at.Dir, akFile))
	}
	return err
}

// attestationKey loads the key, or makes one and has the server trust it.
func (at *Attestor) attestationKey(ctx context.Context, tpm *attest.TPM) (*attest.AK, []byte, error) {
	path := filepath.Join(at.Dir, akFile)
	if raw, err := os.ReadFile(path); err == nil {
		var stored storedAK
		if err := json.Unmarshal(raw, &stored); err == nil {
			if ak, err := tpm.LoadAK(stored.Blob); err == nil {
				return ak, stored.Public, nil
			}
		}
		// The TPM was cleared or replaced: start over with a new key.
		os.Remove(path)
	}
	eks, err := tpm.EKs()
	if err != nil {
		return nil, nil, err
	}
	if len(eks) == 0 {
		return nil, nil, errors.New("the TPM has no endorsement key")
	}
	ek := eks[0]
	ekDER, err := x509.MarshalPKIXPublicKey(ek.Public)
	if err != nil {
		return nil, nil, err
	}
	ak, err := tpm.NewAK(nil)
	if err != nil {
		return nil, nil, err
	}
	params := ak.AttestationParameters()
	registration := api.TPMRegistration{
		EKPublic: ekDER, AKPublic: params.Public, CreateData: params.CreateData,
		CreateAttestation: params.CreateAttestation, CreateSignature: params.CreateSignature,
	}
	if ek.Certificate != nil {
		registration.EKCertificate = ek.Certificate.Raw
	}
	var challenge api.TPMChallenge
	if err := at.exchange(ctx, "/agent/tpm/register", registration, &challenge); err != nil {
		ak.Close(tpm)
		return nil, nil, err
	}
	secret, err := ak.ActivateCredentialWithEK(tpm, attest.EncryptedCredential{Credential: challenge.Credential, Secret: challenge.Secret}, ek)
	if err != nil {
		ak.Close(tpm)
		return nil, nil, fmt.Errorf("the TPM did not take the challenge: %w", err)
	}
	if err := at.exchange(ctx, "/agent/tpm/activate", api.TPMActivation{Secret: secret}, nil); err != nil {
		ak.Close(tpm)
		return nil, nil, err
	}
	blob, err := ak.Marshal()
	if err == nil {
		var raw []byte
		raw, err = json.Marshal(storedAK{Blob: blob, Public: params.Public})
		if err == nil {
			err = writeAtomicSync(path, raw, 0o600)
		}
	}
	if err != nil {
		ak.Close(tpm)
		return nil, nil, err
	}
	return ak, params.Public, nil
}

// sendQuote has the TPM sign its PCRs with a nonce of the server, and sends
// them with the event log that explains them.
func (at *Attestor) sendQuote(ctx context.Context, tpm *attest.TPM, ak *attest.AK, public []byte) error {
	var nonce api.TPMNonce
	if err := at.exchange(ctx, "/agent/tpm/nonce", struct{}{}, &nonce); err != nil {
		return err
	}
	log := at.EventLog
	if log == nil {
		var err error
		// Read here rather than in AttestPlatform, which hides why it failed.
		if log, err = tpm.MeasurementLog(); err != nil {
			return err
		}
	}
	platform, err := tpm.AttestPlatform(ak, nonce.Nonce, &attest.PlatformAttestConfig{EventLog: log})
	if err != nil {
		return err
	}
	quote := api.TPMQuote{AKPublic: public, EventLog: platform.EventLog}
	for _, q := range platform.Quotes {
		quote.Quotes = append(quote.Quotes, api.TPMQuoteSig{Quote: q.Quote, Signature: q.Signature})
	}
	for _, p := range platform.PCRs {
		quote.PCRs = append(quote.PCRs, api.TPMPCR{Index: p.Index, Digest: p.Digest, Hash: uint(p.DigestAlg)})
	}
	return at.exchange(ctx, "/agent/tpm/quote", quote, nil)
}

// exchange posts to the server and reads its answer into out, if any.
func (at *Attestor) exchange(ctx context.Context, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, at.Server+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	resp, err := at.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxTPMResponse))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var failure struct {
			Code string `json:"code"`
		}
		json.Unmarshal(data, &failure)
		if failure.Code == api.ErrTPMUnknown {
			return errTPMUnknown
		}
		return fmt.Errorf("%s: status %d %s", path, resp.StatusCode, failure.Code)
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}
