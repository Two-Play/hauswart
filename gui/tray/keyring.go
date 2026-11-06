package tray

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// SecretTool keeps the password in the keyring of the desktop, where the script
// of the drive looks for it. It goes over stdin, so that no process list shows it.
type SecretTool struct{}

func (SecretTool) StoreNextcloud(password string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "secret-tool", "store", "--label=Nextcloud", "service", "hauswart-nextcloud")
	cmd.Stdin = strings.NewReader(password)
	if out, err := cmd.CombinedOutput(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return errors.New("secret-tool is not installed")
		}
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	// Failing here is fine: the drive also starts at the next login.
	exec.CommandContext(ctx, "systemctl", "--user", "restart", "hauswart-nextcloud.service").Run()
	return nil
}
