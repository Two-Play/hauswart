package server

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestCommandLineLeavesOutWhatUpdatesChange(t *testing.T) {
	for in, want := range map[string]string{
		"kernel_cmdline: /boot/vmlinuz-6.17.1-300.fc43.x86_64 root=UUID=abc ro rhgb quiet\x00":   "root=UUID=abc ro rhgb quiet",
		"kernel_cmdline: BOOT_IMAGE=(hd0,gpt2)/vmlinuz-6.17 root=UUID=abc ro init=/bin/bash":     "root=UUID=abc ro init=/bin/bash",
		"kernel_cmdline: (hd0,gpt3)/ostree/x/vmlinuz-6.17 ostree=/ostree/boot.1/fedora/abc/0 rw": "rw",
	} {
		got, ok := commandLine([]byte(in))
		if !ok || got != want {
			t.Errorf("%q: got %q %v", in, got, ok)
		}
	}
	if _, ok := commandLine([]byte("grub_cmd: set timeout=5")); ok {
		t.Error("a grub command counts as the command line")
	}
	// systemd-stub measures the command line of a unified kernel as UTF-16.
	units := utf16.Encode([]rune("root=UUID=abc ro quiet\x00"))
	raw := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(raw[2*i:], u)
	}
	if got, ok := commandLine(raw); !ok || got != "root=UUID=abc ro quiet" {
		t.Errorf("UTF-16: got %q %v", got, ok)
	}
}
