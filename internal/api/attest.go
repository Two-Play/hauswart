package api

import (
	"maps"
	"time"
)

// The TPM of a device proves how it started. These are the messages between the
// agent and the server, and what the dashboard shows of it.

// TPMRegistration asks the server to trust an attestation key. The EK is the
// TPM's own key; the AK fields are the TPM's statement that it made the AK.
type TPMRegistration struct {
	// EKPublic is the PKIX encoding of the endorsement key.
	EKPublic []byte `json:"ek_public"`
	// EKCertificate is the manufacturer's certificate, if the TPM has one.
	EKCertificate     []byte `json:"ek_certificate,omitempty"`
	AKPublic          []byte `json:"ak_public"`
	CreateData        []byte `json:"create_data"`
	CreateAttestation []byte `json:"create_attestation"`
	CreateSignature   []byte `json:"create_signature"`
}

// TPMChallenge is what only the TPM holding the EK and the AK can decrypt.
type TPMChallenge struct {
	Credential []byte `json:"credential"`
	Secret     []byte `json:"secret"`
}

// TPMActivation returns the decrypted secret.
type TPMActivation struct {
	Secret []byte `json:"secret"`
}

// TPMNonce is the value a quote must contain, so it cannot be an old one.
type TPMNonce struct {
	Nonce []byte `json:"nonce"`
}

// TPMQuote is the signed state of the PCRs, with the event log that explains it.
type TPMQuote struct {
	AKPublic []byte        `json:"ak_public"`
	Quotes   []TPMQuoteSig `json:"quotes"`
	PCRs     []TPMPCR      `json:"pcrs"`
	EventLog []byte        `json:"event_log"`
}

type TPMQuoteSig struct {
	Quote     []byte `json:"quote"`
	Signature []byte `json:"signature"`
}

type TPMPCR struct {
	Index  int    `json:"index"`
	Digest []byte `json:"digest"`
	// Hash is the crypto.Hash of the bank.
	Hash uint `json:"hash"`
}

// Limits of what a device may send. A real event log is a few dozen KB, and a
// TPM has up to five PCR banks of 24.
const (
	MaxEventLog  = 1 << 20
	MaxTPMBlob   = 4 << 10
	MaxTPMQuotes = 5
	MaxTPMPCRs   = 5 * 24
)

// BootState is what the server reads from a verified event log.
type BootState struct {
	// SecureBoot is whether the firmware checked what it started.
	SecureBoot bool `json:"secure_boot"`
	// SecureBootKeys stands for the keys that may sign what starts: PK, KEK and db.
	SecureBootKeys string `json:"secure_boot_keys"`
	// Revocations stands for dbx, which updates make longer.
	Revocations string `json:"revocations"`
	// Firmware stands for the firmware code, PCR 0 and 2.
	Firmware string `json:"firmware"`
	// Bootloaders are the digests of the EFI programs that ran, in order.
	Bootloaders []string `json:"bootloaders"`
	// CommandLine is the kernel's, without the path of the kernel, which
	// changes with every update.
	CommandLine string `json:"command_line"`
}

// What can differ from the state an admin accepted.
const (
	BootSecureBootOff = "secure_boot_off"
	BootKeys          = "secure_boot_keys"
	BootCommandLine   = "command_line"
	BootTPM           = "tpm"
	BootQuote         = "quote"
	BootFirmware      = "firmware"
	BootRevocations   = "revocations"
	BootLoader        = "bootloader"
)

// bootAlarms are the changes that need an admin. The others are hints.
var bootAlarms = map[string]bool{
	BootSecureBootOff: true, BootKeys: true, BootCommandLine: true, BootTPM: true, BootQuote: true,
}

// BootAlarm says whether a change needs an admin to look.
func BootAlarm(kind string) bool { return bootAlarms[kind] }

// BootChange is a difference that waits for an admin.
type BootChange struct {
	Kind  string    `json:"kind"`
	Alarm bool      `json:"alarm"`
	At    time.Time `json:"at"`
}

// BootStatus is what the dashboard shows of a device's boot.
type BootStatus struct {
	// Registered says that the device has a trusted attestation key.
	Registered bool `json:"registered"`
	// EK is the fingerprint of the TPM.
	EK       string       `json:"ek,omitempty"`
	Baseline *BootState   `json:"baseline,omitempty"`
	Current  *BootState   `json:"current,omitempty"`
	Changes  []BootChange `json:"changes"`
	// LastAt is the time of the last valid quote.
	LastAt *time.Time `json:"last_at,omitempty"`
	// OtherTPM says that the device came with another TPM, which an admin has
	// to accept before its quotes count.
	OtherTPM string `json:"other_tpm,omitempty"`
}

// Warnings of the boot, next to those of the report.
const (
	WarnBootChanged        = "boot_changed"
	WarnAttestationMissing = "attestation_missing"
)

// Error codes of attestation.
const (
	ErrInvalidTPM   = "invalid_tpm"
	ErrTPMChallenge = "tpm_challenge"
	ErrTPMUnknown   = "tpm_unknown"
)

func init() {
	maps.Copy(Messages, map[string]string{
		ErrInvalidTPM:   "invalid TPM data: %s",
		ErrTPMChallenge: "the TPM did not answer the challenge",
		ErrTPMUnknown:   "this device has no trusted TPM key yet",
	})
}

// CompareBoot lists what differs between the accepted and the current state.
// Bootloaders that change while Secure Boot is on are updates, which Secure
// Boot checked, so they are not listed then.
func CompareBoot(baseline, current BootState) []string {
	var kinds []string
	if baseline.SecureBoot && !current.SecureBoot {
		kinds = append(kinds, BootSecureBootOff)
	}
	// Switching Secure Boot on brings keys where there were none, which is
	// no reason for an alarm.
	if baseline.SecureBoot && current.SecureBoot && baseline.SecureBootKeys != current.SecureBootKeys {
		kinds = append(kinds, BootKeys)
	}
	if baseline.CommandLine != current.CommandLine {
		kinds = append(kinds, BootCommandLine)
	}
	if baseline.Firmware != current.Firmware {
		kinds = append(kinds, BootFirmware)
	}
	if baseline.Revocations != current.Revocations {
		kinds = append(kinds, BootRevocations)
	}
	if !current.SecureBoot && !equalStrings(baseline.Bootloaders, current.Bootloaders) {
		kinds = append(kinds, BootLoader)
	}
	return kinds
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
