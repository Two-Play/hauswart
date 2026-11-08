package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every action on the actions page has an icon and a description in both
// languages, so a new one does not show up as a bare name.
func TestEveryActionHasAnIconAndADescription(t *testing.T) {
	web := filepath.Join("..", "..", "web", "src")
	tasks, err := os.ReadFile(filepath.Join(web, "tasks.ts"))
	if err != nil {
		t.Fatal(err)
	}
	areas := string(tasks)
	areas = areas[strings.Index(areas, "ACTION_AREAS"):]
	areas = areas[:strings.Index(areas, "];")]
	types := regexp.MustCompile(`'([a-z]+\.[a-z]+)'`).FindAllStringSubmatch(areas, -1)
	if len(types) < 20 {
		t.Fatalf("found only %d actions", len(types))
	}
	icons, err := os.ReadFile(filepath.Join(web, "actionIcons.tsx"))
	if err != nil {
		t.Fatal(err)
	}
	all := append([]string{TaskTerminalOpen}, func() []string {
		var list []string
		for _, m := range types {
			list = append(list, m[1])
		}
		return list
	}()...)
	for _, lang := range []string{"en", "de"} {
		raw, err := os.ReadFile(filepath.Join(web, "locales", lang, "actionhelp.json"))
		if err != nil {
			t.Fatal(err)
		}
		var locale struct {
			Help map[string]string `json:"actionHelp"`
		}
		if err := json.Unmarshal(raw, &locale); err != nil {
			t.Fatal(err)
		}
		for _, action := range all {
			if locale.Help[strings.Replace(action, ".", "_", 1)] == "" {
				t.Errorf("%s: no description for %s", lang, action)
			}
		}
	}
	for _, action := range all {
		if !strings.Contains(string(icons), "'"+action+"':") {
			t.Errorf("no icon for %s", action)
		}
	}
}
