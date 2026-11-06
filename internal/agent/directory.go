package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/philippe/hauswart/internal/api"
)

const (
	sssdConfig = "/etc/sssd/conf.d/hauswart.conf"
	sssdDomain = "hauswart"
	sssdCache  = "/var/lib/sss/db/cache_hauswart.ldb"
	// directoryCA is the only CA sssd trusts for the directory.
	directoryCA = "/etc/hauswart-directory-ca.pem"

	mountProfileName = "hauswart"
	mountProfile     = "custom/" + mountProfileName
	mountProfileDir  = "/etc/authselect/custom/" + mountProfileName

	ldapsPort    = "636"
	selinuxTools = "policycoreutils-python-utils"

	authselectTool = "authselect"
	pamUpdateTool  = "pam-auth-update"
)

// sssdPackages are what the directory login needs, by the tool that sets up PAM.
// Only those two are supported: changing PAM by hand on other systems could lock
// everyone out.
var sssdPackages = map[string][]string{
	authselectTool: {"sssd", "sssd-ldap", "oddjob-mkhomedir"},
	pamUpdateTool:  {"sssd", "sssd-ldap", "libpam-sss", "libnss-sss"},
}

// sssdConf follows what Authentik's LDAP outpost serves. Credentials are cached
// without an end, because a laptop on the road has no way to ask.
func sssdConf(d api.DirectoryRule, locals []string) []byte {
	var b strings.Builder
	// The CA has a file of its own, so it has to show here for a change to count.
	fmt.Fprintf(&b, "# CA SHA-256 %x\n", sha256.Sum256([]byte(d.CA)))
	// Named here, as socket activation only starts after a reboot of a device
	// that installed sssd just now.
	fmt.Fprintf(&b, "# Managed by Hauswart\n[sssd]\nservices = nss, pam\ndomains = %s\n\n", sssdDomain)
	// A local account stays local. Without this, a directory account of the same
	// name would log in as that person with its own password, sudo included.
	fmt.Fprintf(&b, "[nss]\nfilter_users = %s\nfilter_groups = root\n\n", strings.Join(locals, ","))
	fmt.Fprintf(&b, "[domain/%s]\n", sssdDomain)
	b.WriteString("id_provider = ldap\nauth_provider = ldap\nchpass_provider = none\naccess_provider = permit\n")
	b.WriteString("cache_credentials = true\noffline_credentials_expiration = 0\nenumerate = false\n")
	// Authentik has no shell for its accounts.
	b.WriteString("default_shell = /bin/bash\n")
	// Below this are the local accounts, which no directory may claim.
	fmt.Fprintf(&b, "min_id = %d\n", mountFirstUID)
	b.WriteString("ldap_schema = rfc2307bis\nldap_tls_reqcert = demand\nldap_id_use_start_tls = false\n")
	b.WriteString("ldap_user_object_class = user\nldap_user_name = cn\nldap_group_object_class = group\nldap_group_name = cn\n")
	fmt.Fprintf(&b, "ldap_tls_cacert = %s\n", directoryCA)
	fmt.Fprintf(&b, "ldap_uri = %s\nldap_search_base = %s\n", d.URI, d.BaseDN)
	fmt.Fprintf(&b, "ldap_default_bind_dn = %s\nldap_default_authtok_type = password\nldap_default_authtok = %s\n", d.BindDN, d.BindPassword)
	return []byte(b.String())
}

func (e *Executor) pamTool() string {
	if e.Has == nil {
		return ""
	}
	for _, tool := range []string{authselectTool, pamUpdateTool} {
		if e.Has(tool) {
			return tool
		}
	}
	return ""
}

// enforceDirectory keeps the device on the directory, and returns the state for
// the report. PAM comes last, so that nothing asks a daemon that is not there.
// Local accounts go on working in every step: sssd comes after the files.
func (pe *PolicyEngine) enforceDirectory(ctx context.Context, rule *api.DirectoryRule, mounts []api.MountRule, o *outcome) string {
	e := pe.exec
	if rule == nil {
		pe.leaveDirectory(ctx, o)
		return ""
	}
	tool := e.pamTool()
	if tool == "" {
		o.deviate(deviationLogin, "login", "this system has neither authselect nor pam-auth-update")
		return checkOff
	}
	if e.Platform.Backend == nil {
		o.deviate(deviationLogin, "login", "no supported package manager found")
		return checkOff
	}
	before := len(o.deviations)
	converge(ctx, o, deviationPackage, sssdPackages[tool], true, e.installedPackages, func(ctx context.Context, names []string) (string, error) {
		return e.packages(ctx, api.TaskPkgInstall, names)
	})
	if len(o.deviations) > before {
		return checkOff
	}

	if err := e.allowLDAPPort(ctx, rule.URI, o); err != nil {
		o.deviate(deviationLogin, "selinux", err)
		return checkOff
	}
	locals, err := e.localAccounts()
	if err != nil {
		o.deviate(deviationLogin, "sssd", err)
		return checkOff
	}
	full := e.path(sssdConfig)
	wanted := sssdConf(*rule, locals)
	current, err := os.ReadFile(full)
	changed := err != nil || !bytes.Equal(current, wanted)
	if changed {
		if err := os.MkdirAll(filepath.Dir(full), 0o711); err != nil {
			o.deviate(deviationLogin, "sssd", err)
			return checkOff
		}
		if err := writeAtomic(e.path(directoryCA), []byte(rule.CA), 0o644); err != nil {
			o.deviate(deviationLogin, "sssd", err)
			return checkOff
		}
		// What another directory said must not outlive it, offline passwords above all.
		if len(current) > 0 && !bytes.Contains(current, []byte("ldap_uri = "+rule.URI+"\n")) {
			e.forgetDirectory(ctx)
		}
		// sssd refuses a file others can read, and it holds a password.
		if err := writeAtomic(full, wanted, 0o600); err != nil {
			o.deviate(deviationLogin, "sssd", err)
			return checkOff
		}
		o.corrected = append(o.corrected, "directory login")
	}
	if err := e.startSSSD(ctx, tool, changed); err != nil {
		o.deviate(deviationLogin, "sssd", err)
		return checkOff
	}
	if err := e.enablePAM(ctx, tool, len(mounts) > 0); err != nil {
		o.deviate(deviationLogin, "pam", err)
		return checkOff
	}
	return checkOn
}

// allowLDAPPort tells SELinux about a port that is not the usual one. It lets sssd
// reach LDAP ports only, and the outpost of Authentik listens on 6636 by default.
// sssd then only reports "permission denied" in its own log.
func (e *Executor) allowLDAPPort(ctx context.Context, uri string, o *outcome) error {
	_, port, found := strings.Cut(strings.TrimPrefix(uri, "ldaps://"), ":")
	if !found || port == ldapsPort || e.Has == nil || !e.Has("selinuxenabled") {
		return nil
	}
	if _, err := e.Run(ctx, "selinuxenabled"); err != nil {
		return nil
	}
	before := len(o.deviations)
	converge(ctx, o, deviationPackage, []string{selinuxTools}, true, e.installedPackages, func(ctx context.Context, names []string) (string, error) {
		return e.packages(ctx, api.TaskPkgInstall, names)
	})
	if len(o.deviations) > before {
		return errors.New("the SELinux tools are missing")
	}
	listed, err := e.Run(ctx, "semanage", "port", "-l")
	if err != nil {
		return fmt.Errorf("semanage: %w", err)
	}
	for line := range strings.Lines(listed) {
		if fields := strings.Fields(line); len(fields) > 2 && fields[0] == "ldap_port_t" && fields[1] == "tcp" &&
			slices.Contains(strings.Split(strings.Join(fields[2:], ""), ","), port) {
			return nil
		}
	}
	if out, err := e.Run(ctx, "semanage", "port", "-a", "-t", "ldap_port_t", "-p", "tcp", port); err != nil {
		return fmt.Errorf("%w: %s", err, clip(out, maxDeviationText))
	}
	return nil
}

func (e *Executor) startSSSD(ctx context.Context, tool string, restart bool) error {
	if restart {
		// Keeping the old configuration until the next boot would be a surprise.
		if out, err := e.Run(ctx, "systemctl", "enable", "sssd"); err != nil {
			return fmt.Errorf("%w: %s", err, clip(out, maxDeviationText))
		}
		if out, err := e.Run(ctx, "systemctl", "restart", "sssd"); err != nil {
			return fmt.Errorf("%w: %s", err, clip(out, maxDeviationText))
		}
	} else if _, err := e.Run(ctx, "systemctl", "is-active", "--quiet", "sssd"); err != nil {
		if out, err := e.Run(ctx, "systemctl", "enable", "--now", "sssd"); err != nil {
			return fmt.Errorf("%w: %s", err, clip(out, maxDeviationText))
		}
	}
	if tool == authselectTool {
		// It makes the home directory at the first login.
		if out, err := e.Run(ctx, "systemctl", "enable", "--now", "oddjobd"); err != nil {
			return fmt.Errorf("%w: %s", err, clip(out, maxDeviationText))
		}
	}
	return nil
}

func (e *Executor) enablePAM(ctx context.Context, tool string, mounts bool) error {
	if tool == pamUpdateTool {
		if raw, err := os.ReadFile(e.path("/etc/pam.d/common-session")); err == nil && bytes.Contains(raw, []byte("pam_mkhomedir")) {
			return nil
		}
		if out, err := e.Run(ctx, "pam-auth-update", "--enable", "mkhomedir"); err != nil {
			return fmt.Errorf("%w: %s", err, clip(out, maxDeviationText))
		}
		return nil
	}
	profile := "sssd"
	if mounts {
		profile = mountProfile
		if err := e.prepareMountProfile(ctx); err != nil {
			return err
		}
	}
	current := strings.Fields(first(e.Run(ctx, "authselect", "current", "--raw")))
	if len(current) > 0 && current[0] == profile && slices.Contains(current, "with-mkhomedir") {
		return nil
	}
	// What the device had stays on, such as a second factor or mDNS for nas.local.
	args := []string{"select", profile}
	if len(current) > 1 {
		args = append(args, current[1:]...)
	}
	if !slices.Contains(args, "with-mkhomedir") {
		args = append(args, "with-mkhomedir")
	}
	if out, err := e.Run(ctx, "authselect", append(args, "--force", "--backup=hauswart")...); err != nil {
		return fmt.Errorf("%w: %s", err, clip(out, maxDeviationText))
	}
	return nil
}

// localAccounts lists the names no directory may answer for.
func (e *Executor) localAccounts() ([]string, error) {
	raw, err := os.ReadFile(e.path("/etc/passwd"))
	if errors.Is(err, os.ErrNotExist) {
		return []string{"root"}, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for line := range strings.Lines(string(raw)) {
		// Anything else in this file could end up in a configuration line.
		if name, _, ok := strings.Cut(line, ":"); ok && localNameRe.MatchString(name) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return slices.Compact(names), nil
}

var localNameRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*[$]?$`)

// forgetDirectory drops what sssd remembers, cached passwords included.
func (e *Executor) forgetDirectory(ctx context.Context) {
	e.Run(ctx, "systemctl", "stop", "sssd")
	if err := os.Remove(e.path(sssdCache)); err != nil && !errors.Is(err, os.ErrNotExist) {
		e.Run(ctx, "sss_cache", "-E")
	}
}

func first(out string, _ error) string { return out }

// prepareMountProfile adds pam_mount to a profile of its own, because authselect
// no longer has a feature for it.
func (e *Executor) prepareMountProfile(ctx context.Context) error {
	dir := e.path(mountProfileDir)
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		if out, err := e.Run(ctx, "authselect", "create-profile", mountProfileName, "--base-on=sssd"); err != nil {
			return fmt.Errorf("%w: %s", err, clip(out, maxDeviationText))
		}
	}
	for _, name := range []string{"system-auth", "password-auth"} {
		path := filepath.Join(dir, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		patched, err := withPamMount(string(raw))
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if patched != string(raw) {
			if err := writeAtomic(path, []byte(patched), 0o644); err != nil {
				return err
			}
		}
	}
	return nil
}

// withPamMount puts pam_mount first in the auth stack. It asks for the password,
// which pam_unix and pam_sss then take over, as pam_sss would otherwise ask for it
// and end the stack. pam_mount cannot sit anywhere else: the stack holds jumps that
// count modules, and one more module in their way would let an account past
// pam_sss without a password. Being optional, it can never decide a login.
func withPamMount(text string) (string, error) {
	if strings.Contains(text, "pam_mount.so") {
		return text, nil
	}
	var out []string
	firstAuth, shared := true, false
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	lastSession := -1
	for i, line := range lines {
		if strings.HasPrefix(line, "session") {
			lastSession = i
		}
	}
	for i, line := range lines {
		if firstAuth && strings.HasPrefix(line, "auth") {
			out = append(out, "auth        optional                                     pam_mount.so")
			firstAuth = false
		}
		if strings.HasPrefix(line, "auth") && strings.Contains(line, "pam_sss.so forward_pass") {
			line = strings.Replace(line, "pam_sss.so forward_pass", "pam_sss.so forward_pass try_first_pass", 1)
			shared = true
		}
		out = append(out, line)
		if i == lastSession {
			out = append(out, "session     optional                                     pam_mount.so disable_interactive")
		}
	}
	if !shared || lastSession < 0 {
		return "", errors.New("found no place for pam_mount")
	}
	return strings.Join(out, "\n") + "\n", nil
}

// leaveDirectory ends the login, and leaves PAM alone: what authselect set up does
// no harm without a domain, and a change there is the one thing that can go wrong.
func (pe *PolicyEngine) leaveDirectory(ctx context.Context, o *outcome) {
	e := pe.exec
	err := os.Remove(e.path(sssdConfig))
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		o.deviate(deviationLogin, "sssd", err)
		return
	}
	if err := os.Remove(e.path(directoryCA)); err != nil && !errors.Is(err, os.ErrNotExist) {
		o.deviate(deviationLogin, "sssd", err)
	}
	e.forgetDirectory(ctx)
	if out, err := e.Run(ctx, "systemctl", "restart", "sssd"); err != nil {
		pe.log.Warn("restarting sssd failed", "err", err, "output", clip(out, maxDeviationText))
	}
	o.corrected = append(o.corrected, "directory login removed")
}
