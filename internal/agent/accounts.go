package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/philippe/hauswart/internal/api"
)

const (
	maxAccounts  = 200
	maxSudoRules = 20
	maxSudoRule  = 200
	sudoTimeout  = 30 * time.Second
	// sudoers can include other files, which the stamp does not see.
	sudoMaxAge = time.Hour
)

// sudoScan holds what sudo said at the last look.
type sudoScan struct {
	stamp string
	rules map[string]sudoRights
}

type sudoRights struct {
	rules   []string
	unknown bool
}

// accounts lists the login accounts. Local files are the source, so accounts
// from a directory service do not appear.
func (e *Executor) accounts(ctx context.Context) []api.Account {
	passwd, err := os.ReadFile(e.path("/etc/passwd"))
	if err != nil {
		return nil
	}
	group, _ := os.ReadFile(e.path("/etc/group"))
	accounts := parseAccounts(string(passwd), string(group))

	names := make([]string, len(accounts))
	for i, a := range accounts {
		names[i] = a.Name
	}
	rights := e.sudoRights(ctx, names)
	var grants map[string]time.Time
	if e.Grants != nil {
		grants = e.Grants.All()
	}
	for i := range accounts {
		a := &accounts[i]
		a.Sudo = rights[a.Name].rules
		a.SudoUnknown = rights[a.Name].unknown
		if expires, ok := grants[a.Name]; ok {
			a.GrantExpires = &expires
		}
	}
	return accounts
}

func parseAccounts(passwd, group string) []api.Account {
	type groupEntry struct {
		name    string
		gid     string
		members []string
	}
	var groups []groupEntry
	for line := range strings.Lines(group) {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) == 4 {
			groups = append(groups, groupEntry{fields[0], fields[2], strings.Split(fields[3], ",")})
		}
	}
	accounts := []api.Account{}
	for line := range strings.Lines(passwd) {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) < 7 {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil || uid < minUserUID || uid >= nobodyUID {
			continue
		}
		account := api.Account{Name: fields[0], UID: uid, Groups: []string{}}
		for _, g := range groups {
			if g.gid == fields[3] || slices.Contains(g.members, fields[0]) {
				account.Groups = append(account.Groups, g.name)
				if api.PrivilegedGroup(g.name) {
					account.Privileged = append(account.Privileged, g.name)
				}
			}
		}
		slices.Sort(account.Groups)
		slices.Sort(account.Privileged)
		accounts = append(accounts, account)
	}
	slices.SortFunc(accounts, func(a, b api.Account) int { return a.UID - b.UID })
	return accounts[:min(len(accounts), maxAccounts)]
}

// sudoRights asks sudo itself, because only it knows what the rules, aliases
// and groups add up to. Every question ends up in the system log, so it asks
// again only after something changed.
func (e *Executor) sudoRights(ctx context.Context, names []string) map[string]sudoRights {
	stamp := e.sudoStamp(names)
	e.insight.mu.Lock()
	scan := e.insight.sudo
	e.insight.mu.Unlock()
	if scan.stamp == stamp {
		return scan.rules
	}
	ctx, cancel := context.WithTimeout(ctx, sudoTimeout)
	defer cancel()
	rights := map[string]sudoRights{}
	for _, name := range names {
		// The name goes to sudo as an argument and comes from a local file, so
		// anything that could read as an option stays out.
		if !api.ValidUser(name) {
			rights[name] = sudoRights{unknown: true}
			continue
		}
		out, err := e.Run(ctx, "sudo", "-n", "-l", "-U", name)
		rights[name] = parseSudoList(out, err)
	}
	e.insight.mu.Lock()
	e.insight.sudo = sudoScan{stamp: stamp, rules: rights}
	e.insight.mu.Unlock()
	return rights
}

// sudoStamp changes with everything that can change the answer of sudo.
func (e *Executor) sudoStamp(names []string) string {
	var b strings.Builder
	fmt.Fprintln(&b, strings.Join(names, ","), time.Now().Truncate(sudoMaxAge).Unix())
	paths := []string{"/etc/passwd", "/etc/group", "/etc/sudoers", "/etc/sudoers.d"}
	if entries, err := os.ReadDir(e.path("/etc/sudoers.d")); err == nil {
		for _, entry := range entries {
			paths = append(paths, filepath.Join("/etc/sudoers.d", entry.Name()))
		}
	}
	for _, p := range paths {
		if info, err := os.Stat(e.path(p)); err == nil {
			fmt.Fprintln(&b, p, info.ModTime().UnixNano(), info.Size())
		}
	}
	return b.String()
}

func parseSudoList(out string, err error) sudoRights {
	if strings.Contains(out, "is not allowed to run sudo") {
		return sudoRights{}
	}
	_, list, found := strings.Cut(out, "may run the following commands on")
	if !found || err != nil {
		return sudoRights{unknown: true}
	}
	_, list, _ = strings.Cut(list, "\n") // the rest of the heading
	rights := sudoRights{}
	for line := range strings.Lines(list) {
		if rule := strings.TrimSpace(line); rule != "" && len(rights.rules) < maxSudoRules {
			rights.rules = append(rights.rules, clip(cleanText(rule), maxSudoRule))
		}
	}
	return rights
}
