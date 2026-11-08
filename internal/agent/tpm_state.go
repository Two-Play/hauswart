package agent

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strings"

	"github.com/Two-Play/hauswart/internal/api"
)

const (
	tpmVersionFile = "/sys/class/tpm/tpm0/tpm_version_major"
	efiDir         = "/sys/firmware/efi"
	// secureBootVar is the EFI variable SecureBoot: four bytes of attributes,
	// then one byte, 1 for on.
	secureBootVar = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
)

var hsiOutputRe = regexp.MustCompile(`HSI:[0-5]!?`)

// tpmState says whether the device has a TPM 2.0. A TPM 1.2 counts as off: it
// cannot prove the boot the way Hauswart asks.
func (e *Executor) tpmState() string {
	raw, err := os.ReadFile(e.path(tpmVersionFile))
	switch {
	case errors.Is(err, os.ErrNotExist):
		return api.CheckOff
	case err != nil:
		return api.CheckUnknown
	case strings.TrimSpace(string(raw)) == "2":
		return api.CheckOn
	}
	return api.CheckOff
}

// secureBootState reads the firmware's own variable, so it needs no mokutil.
func (e *Executor) secureBootState() string {
	if _, err := os.Stat(e.path(efiDir)); errors.Is(err, os.ErrNotExist) {
		return api.BootLegacy
	}
	raw, err := os.ReadFile(e.path(secureBootVar))
	if errors.Is(err, os.ErrNotExist) {
		// UEFI without the variable has no Secure Boot.
		return api.CheckOff
	}
	if err != nil || len(raw) < 5 {
		return api.CheckUnknown
	}
	if raw[len(raw)-1] == 1 {
		return api.CheckOn
	}
	return api.CheckOff
}

// hsiLevel asks fwupd for the Host Security ID, which sums up how well the
// firmware is protected. Empty if fwupd is not there or does not know.
func (e *Executor) hsiLevel(ctx context.Context) string {
	if e.Has != nil && !e.Has("fwupdmgr") {
		return ""
	}
	out, err := e.Run(ctx, "fwupdmgr", "security", "--json")
	if err != nil {
		return ""
	}
	// The JSON has changed between versions, the value itself has not.
	return hsiOutputRe.FindString(out)
}
