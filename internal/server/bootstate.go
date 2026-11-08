package server

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"slices"
	"strings"
	"unicode/utf16"

	"github.com/google/go-attestation/attest"

	"github.com/Two-Play/hauswart/internal/api"
)

// Event types of the TCG PC Client specification that the boot state reads.
const (
	evIPL                        attest.EventType = 0x0000000D
	evEventTag                   attest.EventType = 0x00000006
	evEFIBootServicesApplication attest.EventType = 0x80000003
)

// maxCommandLine keeps what a device claims in its event log to a sane size.
const maxCommandLine = 4096

// readBootState reads the state of a boot from events that were checked
// against quoted PCRs, and the PCRs themselves.
func readBootState(events []attest.Event, pcrs []attest.PCR) api.BootState {
	var state api.BootState
	if sb, err := attest.ParseSecurebootState(events); err == nil {
		state.SecureBoot = sb.Enabled
		state.SecureBootKeys = fingerprint(
			certDigests(sb.PlatformKeys), sb.PlatformKeyHashes,
			certDigests(sb.ExchangeKeys), sb.ExchangeKeyHashes,
			certDigests(sb.PermittedKeys), sb.PermittedHashes)
		state.Revocations = fingerprint(certDigests(sb.ForbiddenKeys), sb.ForbiddenHashes)
	}
	state.Firmware = firmwareDigest(pcrs)
	for _, e := range events {
		switch {
		case e.Index == 4 && e.Type == evEFIBootServicesApplication:
			state.Bootloaders = append(state.Bootloaders, hex.EncodeToString(e.Digest))
		case (e.Index == 8 || e.Index == 12) && (e.Type == evIPL || e.Type == evEventTag):
			if line, ok := commandLine(e.Data); ok {
				state.CommandLine = line
			}
		}
	}
	return state
}

// firmwareDigest stands for the firmware code: PCR 0 holds the platform
// firmware, PCR 2 the code of option ROMs. PCR 1 holds settings such as the boot
// order, which change too often to mean anything.
func firmwareDigest(pcrs []attest.PCR) string {
	h := sha256.New()
	found := false
	for _, index := range []int{0, 2} {
		for _, p := range pcrs {
			if p.Index == index && p.DigestAlg == crypto.SHA256 {
				h.Write(p.Digest)
				found = true
			}
		}
	}
	if !found {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func certDigests(certs []x509.Certificate) [][]byte {
	digests := make([][]byte, 0, len(certs))
	for _, c := range certs {
		sum := sha256.Sum256(c.Raw)
		digests = append(digests, sum[:])
	}
	return digests
}

// fingerprint stands for a few sets of digests. Each set is sorted, since the
// firmware may list the same keys in another order.
func fingerprint(sets ...[][]byte) string {
	h := sha256.New()
	for _, set := range sets {
		sorted := make([]string, 0, len(set))
		for _, d := range set {
			sorted = append(sorted, hex.EncodeToString(d))
		}
		slices.Sort(sorted)
		binary.Write(h, binary.BigEndian, uint32(len(sorted)))
		for _, d := range sorted {
			h.Write([]byte(d))
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// commandLine finds the kernel command line in an event: grub measures it as
// "kernel_cmdline: ...", systemd-stub as UTF-16. The path of the kernel goes,
// because it changes with every update, which Secure Boot checks anyway.
func commandLine(data []byte) (string, bool) {
	text := string(data)
	if utf16Like(data) {
		units := make([]uint16, 0, len(data)/2)
		for i := 0; i+1 < len(data); i += 2 {
			units = append(units, binary.LittleEndian.Uint16(data[i:]))
		}
		text = string(utf16.Decode(units))
	}
	text = strings.TrimRight(text, "\x00")
	line, ok := strings.CutPrefix(text, "kernel_cmdline: ")
	if !ok {
		if !utf16Like(data) {
			return "", false
		}
		line = text
	}
	if len(line) > maxCommandLine {
		line = line[:maxCommandLine]
	}
	var kept []string
	for _, field := range strings.Fields(line) {
		if volatileArgument(field) {
			continue
		}
		kept = append(kept, field)
	}
	return strings.Join(kept, " "), true
}

// volatileArgument says whether a part of the command line names what an
// update replaces: the kernel and initrd, or the deployment of an atomic
// system. grub puts the kernel's path first, without a name.
func volatileArgument(field string) bool {
	for _, prefix := range []string{"BOOT_IMAGE=", "initrd=", "ostree="} {
		if strings.HasPrefix(field, prefix) {
			return true
		}
	}
	return strings.Contains(field, "vmlinuz")
}

// utf16Like says whether data looks like UTF-16LE text: every second byte zero.
func utf16Like(data []byte) bool {
	if len(data) < 4 || len(data)%2 != 0 {
		return false
	}
	for i := 1; i < len(data); i += 2 {
		if data[i] != 0 {
			return false
		}
	}
	return true
}
