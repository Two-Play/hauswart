package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/philippe/hauswart/internal/api"
)

const (
	pamMountConfig = "/etc/security/pam_mount.conf.xml"
	// mountTimeout bounds what a share that is out of reach adds to a login. A
	// laptop on the road must not wait for its NAS.
	mountTimeout = 8
	// mountFirstUID leaves local accounts out, as they have no password that a
	// share would know. It is where Authentik starts counting.
	mountFirstUID = 2000

	nextcloudAutostart = "/etc/xdg/autostart/hauswart-nextcloud.desktop"
	nextcloudUnit      = "/etc/systemd/user/hauswart-nextcloud.service"
	nextcloudScript    = "/usr/local/libexec/hauswart-nextcloud-drive"
)

var (
	mountPackages = map[string][]string{
		authselectTool: {"pam_mount", "cifs-utils"},
		pamUpdateTool:  {"libpam-mount", "cifs-utils"},
	}
	nextcloudClientPackage = map[string]string{authselectTool: "nextcloud-client", pamUpdateTool: "nextcloud-desktop"}
	nextcloudDrivePackages = []string{"rclone", "fuse3", "libsecret"}
	nextcloudDriveDebian   = []string{"rclone", "fuse3", "libsecret-tools"}
)

// pamMountConf describes the shares. All values passed the checks of the policy,
// which allow nothing that means something in XML. The password never appears
// here: pam_mount hands on what was typed at the login. The mount runs as root, so
// the mount point has to be somewhere users cannot write: in a home directory, a
// link in its place would put the share over a system directory.
func pamMountConf(mounts []api.MountRule) []byte {
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n<!-- Managed by Hauswart -->\n<pam_mount>\n")
	b.WriteString("<debug enable=\"0\" />\n<mntoptions allow=\"*\" />\n<mntoptions require=\"nosuid,nodev\" />\n")
	// It asks first now, and should ask like every login does.
	b.WriteString("<msg-authpw>Password: </msg-authpw>\n")
	b.WriteString("<logout wait=\"0\" hup=\"no\" term=\"no\" kill=\"no\" />\n<mkmountpoint enable=\"1\" remove=\"true\" />\n")
	fmt.Fprintf(&b, "<cifsmount>timeout %d mount.cifs //%%(SERVER)/%%(VOLUME) %%(MNTPT) -o username=%%(USER),uid=%%(USERUID),gid=%%(USERGID)%%(before=\\\",\\\" OPTIONS)</cifsmount>\n", mountTimeout)
	for _, mount := range mounts {
		fmt.Fprintf(&b, "<volume uid=\"%d-4294967294\" fstype=\"cifs\" server=\"%s\" path=\"%s\" mountpoint=\"/media/%%(USER)-%s\" options=\"nosuid,nodev,vers=3.0\" />\n",
			mountFirstUID, mount.Server, mount.Share, mount.Folder)
	}
	b.WriteString("</pam_mount>\n")
	return []byte(b.String())
}

func (pe *PolicyEngine) enforceMounts(ctx context.Context, mounts []api.MountRule, directory bool, o *outcome) {
	e := pe.exec
	full := e.path(pamMountConfig)
	if len(mounts) == 0 {
		raw, err := os.ReadFile(full)
		if err == nil && bytes.Contains(raw, []byte("Managed by Hauswart")) {
			// An empty list keeps PAM working, whether pam_mount stays in it or not.
			if err := writeAtomic(full, pamMountConf(nil), 0o644); err != nil {
				o.deviate(deviationMount, "pam_mount", err)
			}
		}
		return
	}
	if !directory {
		o.deviate(deviationMount, "shares", "shares need a working directory login")
		return
	}
	tool := e.pamTool()
	before := len(o.deviations)
	converge(ctx, o, deviationPackage, mountPackages[tool], true, e.installedPackages, func(ctx context.Context, names []string) (string, error) {
		return e.packages(ctx, api.TaskPkgInstall, names)
	})
	if len(o.deviations) > before {
		return
	}
	wanted := pamMountConf(mounts)
	current, err := os.ReadFile(full)
	if err == nil && bytes.Equal(current, wanted) {
		return
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		o.deviate(deviationMount, "pam_mount", err)
		return
	}
	if err := writeAtomic(full, wanted, 0o644); err != nil {
		o.deviate(deviationMount, "pam_mount", err)
		return
	}
	o.corrected = append(o.corrected, "shares")
}

func nextcloudDesktop(url string) []byte {
	return fmt.Appendf(nil, "[Desktop Entry]\nType=Application\nName=Nextcloud\nExec=nextcloud --background --overrideserverurl %s\nX-GNOME-Autostart-Delay=5\n", url)
}

// nextcloudDriveScript takes the app password from the keyring of the person who
// runs it, so it is on no disk and in no process list.
func nextcloudDriveScript(url string) []byte {
	return fmt.Appendf(nil, `#!/bin/sh
# Managed by Hauswart
set -e
# Without a keyring yet, systemd tries again.
secret=$(secret-tool lookup service hauswart-nextcloud) || exit 1
mkdir -p "$HOME/Nextcloud"
RCLONE_WEBDAV_PASS=$(printf '%%s' "$secret" | rclone obscure -)
export RCLONE_WEBDAV_PASS
exec rclone mount ":webdav:" "$HOME/Nextcloud" \
	--webdav-url "%s/remote.php/dav/files/$USER" --webdav-vendor nextcloud --webdav-user "$USER" \
	--vfs-cache-mode writes
`, url)
}

const nextcloudUnitText = `# Managed by Hauswart
[Unit]
Description=Nextcloud as a network drive
After=graphical-session.target
StartLimitIntervalSec=0

[Service]
ExecStart=` + nextcloudScript + `
Restart=on-failure
RestartSec=60

[Install]
WantedBy=default.target
`

// enforceNextcloud sets the cloud up for everyone on the device. Logging in stays
// with each person, so that no password of theirs is ever in a policy.
func (pe *PolicyEngine) enforceNextcloud(ctx context.Context, rule *api.NextcloudRule, o *outcome) {
	e := pe.exec
	files := map[string]fileWanted{}
	if rule != nil {
		tool := e.pamTool()
		if tool == "" {
			o.deviate(deviationMount, "nextcloud", "this system has neither authselect nor pam-auth-update")
			return
		}
		var packages []string
		switch {
		case rule.Mode == api.NextcloudClient:
			packages = []string{nextcloudClientPackage[tool]}
			files[nextcloudAutostart] = fileWanted{nextcloudDesktop(rule.URL), 0o644}
		case tool == pamUpdateTool:
			packages = nextcloudDriveDebian
		default:
			packages = nextcloudDrivePackages
		}
		if rule.Mode == api.NextcloudDrive {
			files[nextcloudScript] = fileWanted{nextcloudDriveScript(rule.URL), 0o755}
			files[nextcloudUnit] = fileWanted{[]byte(nextcloudUnitText), 0o644}
		}
		before := len(o.deviations)
		converge(ctx, o, deviationPackage, packages, true, e.installedPackages, func(ctx context.Context, names []string) (string, error) {
			return e.packages(ctx, api.TaskPkgInstall, names)
		})
		if len(o.deviations) > before {
			return
		}
	}
	changed := false
	for _, path := range []string{nextcloudAutostart, nextcloudScript, nextcloudUnit} {
		full := e.path(path)
		want, ok := files[path]
		if !ok {
			if err := os.Remove(full); err == nil {
				changed = true
			} else if !errors.Is(err, os.ErrNotExist) {
				o.deviate(deviationMount, path, err)
			}
			continue
		}
		if current, err := os.ReadFile(full); err == nil && bytes.Equal(current, want.content) {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			o.deviate(deviationMount, path, err)
			continue
		}
		if err := writeAtomic(full, want.content, want.mode); err != nil {
			o.deviate(deviationMount, path, err)
			continue
		}
		changed = true
	}
	if changed {
		o.corrected = append(o.corrected, "nextcloud")
	}
	// A global enable, so that the drive starts for everyone who has set it up.
	// It is repeated every time, so that a failure does not stay unnoticed.
	if rule != nil && rule.Mode == api.NextcloudDrive {
		if out, err := e.Run(ctx, "systemctl", "--global", "enable", "hauswart-nextcloud.service"); err != nil {
			o.deviate(deviationMount, "nextcloud", strings.TrimSpace(out+" "+err.Error()))
		}
	} else if changed {
		e.Run(ctx, "systemctl", "--global", "disable", "hauswart-nextcloud.service")
	}
}

type fileWanted struct {
	content []byte
	mode    os.FileMode
}
