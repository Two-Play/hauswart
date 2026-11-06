package agent

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

const firefoxPolicyDir = "/etc/firefox/policies"

// chromiumPolicyDirs are the managed policy directories of the Chromium family.
// The snap has its own, and test/vm.py measures it.
var chromiumPolicyDirs = []string{
	"/etc/chromium/policies/managed",
	"/etc/opt/chrome/policies/managed",
	"/var/snap/chromium/current/policies/managed",
}

// trustInBrowsers covers distributions whose browsers ignore the system store,
// which test/browsers.py measures. Each browser gets the CA through a policy.
func (e *Executor) trustInBrowsers(name, certPEM string) error {
	return errors.Join(e.firefoxPolicy(name, certPEM), e.chromiumPolicies(name, certPEM))
}

// firefoxPolicy adds the CA to policies.json. That single file may hold
// settings from someone else, so they stay. The certificate sits next to it,
// because a snap cannot read most other paths.
func (e *Executor) firefoxPolicy(name, certPEM string) error {
	dir := e.path(firefoxPolicyDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	certPath := filepath.Join(firefoxPolicyDir, "hauswart-"+name+".crt")
	if err := writeAtomic(e.path(certPath), []byte(certPEM), 0o644); err != nil {
		return err
	}

	file := filepath.Join(dir, "policies.json")
	doc := map[string]any{}
	raw, err := os.ReadFile(file)
	if err == nil {
		if err := json.Unmarshal(raw, &doc); err != nil {
			return fmt.Errorf("%s is not valid JSON, leaving it alone: %w", firefoxPolicyDir, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	policies, err := section(doc, "policies")
	if err != nil {
		return err
	}
	certificates, err := section(policies, "Certificates")
	if err != nil {
		return err
	}
	install, _ := certificates["Install"].([]any)
	if !slices.Contains(install, any(certPath)) {
		certificates["Install"] = append(install, certPath)
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(file, out, 0o644)
}

func section(parent map[string]any, key string) (map[string]any, error) {
	value, ok := parent[key]
	if !ok {
		child := map[string]any{}
		parent[key] = child
		return child, nil
	}
	child, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected type of %q in the Firefox policies", key)
	}
	return child, nil
}

// chromiumPolicies writes one file per CA, so there is nothing to merge.
func (e *Executor) chromiumPolicies(name, certPEM string) error {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return errors.New("not a PEM certificate")
	}
	raw, err := json.Marshal(map[string][]string{"CACertificates": {base64.StdEncoding.EncodeToString(block.Bytes)}})
	if err != nil {
		return err
	}
	var errs []error
	for _, dir := range chromiumPolicyDirs {
		// The snap's directory exists only with the snap installed. Creating
		// it would also create the snap's state directory, which is not ours.
		if dir == chromiumPolicyDirs[2] {
			if _, err := os.Stat(e.path("/var/snap/chromium/current")); err != nil {
				continue
			}
		}
		target := e.path(dir)
		if err := os.MkdirAll(target, 0o755); err != nil {
			errs = append(errs, err)
			continue
		}
		errs = append(errs, writeAtomic(filepath.Join(target, "hauswart-"+name+".json"), raw, 0o644))
	}
	return errors.Join(errs...)
}

// untrustInBrowsers undoes trustInBrowsers. Other settings in the Firefox
// policies stay, like everything that was not added here.
func (e *Executor) untrustInBrowsers(name string) error {
	errs := []error{e.removeFirefoxPolicy(name)}
	for _, dir := range chromiumPolicyDirs {
		err := os.Remove(e.path(filepath.Join(dir, "hauswart-"+name+".json")))
		if !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (e *Executor) removeFirefoxPolicy(name string) error {
	certPath := filepath.Join(firefoxPolicyDir, "hauswart-"+name+".crt")
	if err := os.Remove(e.path(certPath)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file := e.path(filepath.Join(firefoxPolicyDir, "policies.json"))
	raw, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	doc := map[string]any{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("%s is not valid JSON, leaving it alone: %w", firefoxPolicyDir, err)
	}
	policies, _ := doc["policies"].(map[string]any)
	certificates, _ := policies["Certificates"].(map[string]any)
	install, _ := certificates["Install"].([]any)
	if !slices.Contains(install, any(certPath)) {
		return nil
	}
	certificates["Install"] = slices.DeleteFunc(install, func(entry any) bool { return entry == any(certPath) })
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(file, out, 0o644)
}
