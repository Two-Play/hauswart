package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Two-Play/hauswart/internal/api"
)

func writeFake(t *testing.T, root, path string, data []byte) {
	t.Helper()
	full := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestTPMAndSecureBoot(t *testing.T) {
	e, _ := newExecutor(t)
	if got := e.tpmState(); got != api.CheckOff {
		t.Errorf("no TPM: %s", got)
	}
	if got := e.secureBootState(); got != api.BootLegacy {
		t.Errorf("no UEFI: %s", got)
	}
	writeFake(t, e.Root, tpmVersionFile, []byte("1\n"))
	if got := e.tpmState(); got != api.CheckOff {
		t.Errorf("TPM 1.2: %s", got)
	}
	writeFake(t, e.Root, tpmVersionFile, []byte("2\n"))
	if got := e.tpmState(); got != api.CheckOn {
		t.Errorf("TPM 2.0: %s", got)
	}
	os.MkdirAll(filepath.Join(e.Root, efiDir), 0o755)
	if got := e.secureBootState(); got != api.CheckOff {
		t.Errorf("UEFI without the variable: %s", got)
	}
	writeFake(t, e.Root, secureBootVar, []byte{6, 0, 0, 0, 1})
	if got := e.secureBootState(); got != api.CheckOn {
		t.Errorf("Secure Boot on: %s", got)
	}
	writeFake(t, e.Root, secureBootVar, []byte{6, 0, 0, 0, 0})
	if got := e.secureBootState(); got != api.CheckOff {
		t.Errorf("Secure Boot off: %s", got)
	}
}

func TestHSILevel(t *testing.T) {
	e, _ := newExecutor(t)
	e.Run = func(_ context.Context, name string, args ...string) (string, error) {
		return `{"HostSecurityAttributes":[{"AppstreamId":"org.fwupd.hsi.Tpm"}],"HostSecurityId":"HSI:2! (v2.0.8)"}`, nil
	}
	if got := e.hsiLevel(context.Background()); got != "HSI:2!" {
		t.Errorf("got %q", got)
	}
	e.Has = func(string) bool { return false }
	if got := e.hsiLevel(context.Background()); got != "" {
		t.Errorf("without fwupd: %q", got)
	}
}
