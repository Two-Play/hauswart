package agent

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/Two-Play/hauswart/internal/api"
)

// Version is set at build time.
var Version = "dev"

// Backend maps abstract package operations to one package manager. Adding a
// distribution means adding an entry here; nothing else knows about distros.
type Backend struct {
	Name    string
	Install func(pkgs []string) []string
	Remove  func(pkgs []string) []string
	Upgrade func() []string
	// Refresh comes before an install, if the package manager does not look for
	// itself. A fresh Debian knows no packages at all before it.
	Refresh []string
	// Query asks whether a package is there, and Present reads the answer. A
	// name can be what another package provides, as vim is on Fedora.
	Query   func(pkg string) []string
	Present func(out string, err error) bool
	// List prints what is installed, for parseInstalled.
	List []string
	// Available prints the names of what could be installed, for
	// parseCatalog. Without it, searches only find what is installed.
	Available []string
}

func rpmQuery(pkg string) []string { return []string{"rpm", "-q", "--whatprovides", pkg} }

var rpmList = []string{"rpm", "-qa", "--qf", "%{NAME} %{EVR}\\n"}

func exitedCleanly(_ string, err error) bool { return err == nil }

// Trust describes how a distribution manages its system CA store.
type Trust struct {
	Dir    string
	Update []string
	// Browsers is set where measurements show that browsers ignore the system
	// store, so they need a policy as well.
	Browsers bool
}

type Platform struct {
	Distro  string
	Backend *Backend
	Flatpak bool
	Trust   *Trust
	// Firewall is firewalld, ufw, or empty if neither is installed.
	Firewall string
}

func simpleBackend(name string, install, remove, upgrade []string) *Backend {
	withPkgs := func(base []string) func([]string) []string {
		return func(pkgs []string) []string {
			argv := append([]string{}, base...)
			return append(argv, pkgs...)
		}
	}
	return &Backend{
		Name:    name,
		Install: withPkgs(install),
		Remove:  withPkgs(remove),
		Upgrade: func() []string { return upgrade },
		Query:   rpmQuery,
		Present: exitedCleanly,
		List:    rpmList,
	}
}

// Order matters: an atomic Fedora ships rpm-ostree and may also have dnf,
// which must not be used there.
func detectBackend(has func(string) bool, atomic bool) *Backend {
	switch {
	case atomic && has("rpm-ostree"):
		// rpm-ostree treats "--" as the end of its arguments and then sees no
		// package at all. Names are validated to not start with a dash.
		return simpleBackend("rpm-ostree",
			// Without --apply-live, a package only appears after a reboot, while
			// the task already reports success.
			[]string{"rpm-ostree", "install", "--idempotent", "--apply-live"},
			[]string{"rpm-ostree", "uninstall"},
			[]string{"rpm-ostree", "upgrade"})
	case has("dnf5"):
		// Like rpm-ostree, the dnf5 of a freshly installed Fedora 44 refuses "--".
		// Names are validated to not start with a dash.
		backend := simpleBackend("dnf5",
			[]string{"dnf5", "install", "-y"},
			[]string{"dnf5", "remove", "-y"},
			[]string{"dnf5", "upgrade", "-y"})
		backend.Available = []string{"dnf5", "-q", "repoquery", "--available", "--qf", "%{name}\\n"}
		return backend
	case has("dnf"):
		backend := simpleBackend("dnf",
			[]string{"dnf", "install", "-y", "--"},
			[]string{"dnf", "remove", "-y", "--"},
			[]string{"dnf", "upgrade", "-y"})
		backend.Available = []string{"dnf", "-q", "repoquery", "--available", "--qf", "%{name}"}
		return backend
	case has("apt-get"):
		return &Backend{
			Name:    "apt",
			Install: func(p []string) []string { return append([]string{"apt-get", "install", "-y", "--"}, p...) },
			Remove:  func(p []string) []string { return append([]string{"apt-get", "remove", "-y", "--"}, p...) },
			Upgrade: func() []string { return []string{"sh", "-c", "apt-get update && apt-get upgrade -y"} },
			Refresh: []string{"apt-get", "update"},
			// A removed package stays known to dpkg, so the exit code says nothing.
			Query: func(pkg string) []string { return []string{"dpkg-query", "-W", "-f=${db:Status-Status}", pkg} },
			Present: func(out string, err error) bool {
				return err == nil && strings.TrimSpace(out) == "installed"
			},
			List:      []string{"dpkg-query", "-W", "-f=${db:Status-Status} ${binary:Package} ${Version}\\n"},
			Available: []string{"apt-cache", "pkgnames"},
		}
	case has("zypper"):
		backend := simpleBackend("zypper",
			[]string{"zypper", "--non-interactive", "install", "--"},
			[]string{"zypper", "--non-interactive", "remove", "--"},
			[]string{"zypper", "--non-interactive", "update"})
		backend.Available = []string{"zypper", "--non-interactive", "-q", "search", "-t", "package"}
		return backend
	case has("pacman"):
		backend := simpleBackend("pacman",
			[]string{"pacman", "-S", "--noconfirm", "--needed", "--"},
			[]string{"pacman", "-R", "--noconfirm", "--"},
			[]string{"pacman", "-Syu", "--noconfirm"})
		backend.Query = func(pkg string) []string { return []string{"pacman", "-Q", pkg} }
		backend.List = []string{"pacman", "-Q"}
		backend.Available = []string{"pacman", "-Slq"}
		return backend
	}
	return nil
}

func detectTrust(has func(string) bool, dirExists func(string) bool) *Trust {
	switch {
	// Fedora and Arch both ship update-ca-trust but read different
	// directories, so the command alone does not identify the layout.
	case has("update-ca-trust") && dirExists("/etc/pki/ca-trust/source"):
		return &Trust{Dir: "/etc/pki/ca-trust/source/anchors", Update: []string{"update-ca-trust", "extract"}}
	case has("update-ca-trust") && dirExists("/etc/ca-certificates/trust-source"):
		return &Trust{Dir: "/etc/ca-certificates/trust-source/anchors", Update: []string{"update-ca-trust", "extract"}}
	case has("update-ca-certificates") && dirExists("/etc/pki/trust/anchors"):
		// openSUSE: Firefox and Chromium ignore the store there as well.
		return &Trust{Dir: "/etc/pki/trust/anchors", Update: []string{"update-ca-certificates"}, Browsers: true}
	case has("update-ca-certificates"):
		return &Trust{Dir: "/usr/local/share/ca-certificates", Update: []string{"update-ca-certificates"}, Browsers: true}
	case has("trust"):
		return &Trust{Dir: "/etc/ca-certificates/trust-source/anchors", Update: []string{"trust", "extract-compat"}}
	}
	return nil
}

// Detect inspects the running system.
func Detect() Platform {
	has := func(name string) bool {
		_, err := exec.LookPath(name)
		return err == nil
	}
	dirExists := func(p string) bool {
		info, err := os.Stat(p)
		return err == nil && info.IsDir()
	}
	_, err := os.Stat("/run/ostree-booted")
	return Platform{
		Distro:   distroName(),
		Backend:  detectBackend(has, err == nil),
		Flatpak:  has("flatpak"),
		Trust:    detectTrust(has, dirExists),
		Firewall: detectFirewall(has),
	}
}

func detectFirewall(has func(string) bool) string {
	switch {
	case has("firewall-cmd"):
		return firewallD
	case has("ufw"):
		return firewallUFW
	}
	return ""
}

func distroName() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return runtime.GOOS
	}
	return parseOSRelease(data)
}

func parseOSRelease(data []byte) string {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		if value, ok := strings.CutPrefix(scanner.Text(), "PRETTY_NAME="); ok {
			return strings.Trim(value, `"'`)
		}
	}
	return "Linux"
}

// Collect builds the current report.
func Collect(p Platform) api.Report {
	r := api.Report{Distro: p.Distro, AgentVersion: Version, CPUs: runtime.NumCPU()}
	r.Hostname, _ = os.Hostname()
	if p.Backend != nil {
		r.Backends = append(r.Backends, p.Backend.Name)
	}
	if p.Flatpak {
		r.Backends = append(r.Backends, "flatpak")
	}
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		r.Kernel = strings.TrimSpace(string(data))
	}
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		if fields := strings.Fields(string(data)); len(fields) > 0 {
			r.Load1, _ = strconv.ParseFloat(fields[0], 64)
		}
	}
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		if fields := strings.Fields(string(data)); len(fields) > 0 {
			seconds, _ := strconv.ParseFloat(fields[0], 64)
			r.Uptime = int64(seconds)
		}
	}
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		r.MemTotal, r.MemUsed = parseMeminfo(data)
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs("/", &fs); err == nil {
		size := uint64(fs.Bsize)
		r.DiskTotal = fs.Blocks * size
		r.DiskUsed = (fs.Blocks - fs.Bfree) * size
	}
	return r
}

func parseMeminfo(data []byte) (total, used uint64) {
	var available uint64
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			total = kb * 1024
		case "MemAvailable:":
			available = kb * 1024
		}
	}
	if available > total {
		return total, 0
	}
	return total, total - available
}
