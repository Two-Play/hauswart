package api

import (
	"slices"
	"testing"
)

func TestCompareBoot(t *testing.T) {
	base := BootState{SecureBoot: true, SecureBootKeys: "k", Revocations: "r", Firmware: "f",
		Bootloaders: []string{"shim", "grub"}, CommandLine: "root=UUID=1 ro quiet"}
	for name, c := range map[string]struct {
		change func(*BootState)
		want   []string
	}{
		"nothing":                      {func(*BootState) {}, nil},
		"an update of grub":            {func(s *BootState) { s.Bootloaders = []string{"shim", "grub2"} }, nil},
		"secure boot off":              {func(s *BootState) { s.SecureBoot = false; s.Bootloaders = []string{"evil"} }, []string{BootSecureBootOff, BootLoader}},
		"another key in db":            {func(s *BootState) { s.SecureBootKeys = "k2" }, []string{BootKeys}},
		"a shell instead of init":      {func(s *BootState) { s.CommandLine += " init=/bin/bash" }, []string{BootCommandLine}},
		"a firmware update":            {func(s *BootState) { s.Firmware = "f2" }, []string{BootFirmware}},
		"a longer list of revocations": {func(s *BootState) { s.Revocations = "r2" }, []string{BootRevocations}},
	} {
		current := base
		current.Bootloaders = slices.Clone(base.Bootloaders)
		c.change(&current)
		if got := CompareBoot(base, current); !slices.Equal(got, c.want) {
			t.Errorf("%s: got %v, want %v", name, got, c.want)
		}
	}
	for kind, alarm := range map[string]bool{BootSecureBootOff: true, BootKeys: true, BootCommandLine: true, BootTPM: true,
		BootQuote: true, BootFirmware: false, BootRevocations: false, BootLoader: false} {
		if BootAlarm(kind) != alarm {
			t.Errorf("%s: alarm %v", kind, !alarm)
		}
	}
}

func TestSwitchingSecureBootOnIsNoAlarm(t *testing.T) {
	off := BootState{Firmware: "f", CommandLine: "ro"}
	on := BootState{SecureBoot: true, SecureBootKeys: "k", Firmware: "f", CommandLine: "ro"}
	if got := CompareBoot(off, on); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}
