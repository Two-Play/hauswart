package api

import (
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// MaxInventoryPackages is far above a desktop, and keeps a report below the
	// limit of a request.
	MaxInventoryPackages = 15000
	maxInventoryDisks    = 64
	maxInventoryNICs     = 64
	maxNICAddresses      = 32
	maxInventoryText     = 256
	maxAssetText         = 128
	maxAssetNote         = 2000

	PackageSystem  = "package"
	PackageFlatpak = "flatpak"

	// The values of a security check.
	CheckOn      = "on"
	CheckOff     = "off"
	CheckUnknown = "unknown"
)

// Inventory is what a device says about itself. Nothing here is proven, so it is
// for reading and never decides anything.
type Inventory struct {
	Hardware Hardware      `json:"hardware"`
	Disks    []Disk        `json:"disks,omitempty"`
	Network  []NetworkCard `json:"network,omitempty"`
	Security SecurityState `json:"security"`
	Packages []Package     `json:"packages,omitempty"`
	// Truncated says that the device had more packages than it may send.
	Truncated bool `json:"truncated,omitempty"`
}

type Hardware struct {
	Vendor string `json:"vendor,omitempty"`
	Model  string `json:"model,omitempty"`
	Serial string `json:"serial,omitempty"`
	BIOS   string `json:"bios,omitempty"`
	CPU    string `json:"cpu,omitempty"`
}

type Disk struct {
	Name       string `json:"name"`
	Model      string `json:"model,omitempty"`
	Size       uint64 `json:"size"`
	Rotational bool   `json:"rotational,omitempty"`
}

type NetworkCard struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
}

// SecurityState holds CheckOn, CheckOff or CheckUnknown, with or without a policy.
type SecurityState struct {
	DiskEncryption string `json:"disk_encryption,omitempty"`
	ScreenLock     string `json:"screen_lock,omitempty"`
	Firewall       string `json:"firewall,omitempty"`
}

type Package struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// Asset is what only people know about a device.
type Asset struct {
	Tag           string `json:"tag,omitempty"`
	Person        string `json:"person,omitempty"`
	Location      string `json:"location,omitempty"`
	Purchased     string `json:"purchased,omitempty"`
	WarrantyUntil string `json:"warranty_until,omitempty"`
	Note          string `json:"note,omitempty"`
}

var macRe = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5,19}$`)

func validText(s string, limit int, lines bool) bool {
	if len(s) > limit || !utf8.ValidString(s) {
		return false
	}
	return !strings.ContainsFunc(s, func(r rune) bool {
		return unicode.IsControl(r) && !(lines && r == '\n')
	})
}

// Check keeps out what would hurt the server or a reader. A device can still lie.
func (i Inventory) Check() error {
	if len(i.Packages) > MaxInventoryPackages || len(i.Disks) > maxInventoryDisks || len(i.Network) > maxInventoryNICs {
		return Fail(ErrInvalidInventory, "too many entries")
	}
	h := i.Hardware
	for _, text := range []string{h.Vendor, h.Model, h.Serial, h.BIOS, h.CPU} {
		if !validText(text, maxInventoryText, false) {
			return Fail(ErrInvalidInventory, "hardware")
		}
	}
	for _, disk := range i.Disks {
		if disk.Name == "" || !validText(disk.Name, maxInventoryText, false) || !validText(disk.Model, maxInventoryText, false) {
			return Fail(ErrInvalidInventory, "disk")
		}
	}
	for _, card := range i.Network {
		if card.Name == "" || !validText(card.Name, maxInventoryText, false) || card.MAC != "" && !macRe.MatchString(card.MAC) ||
			len(card.Addresses) > maxNICAddresses {
			return Fail(ErrInvalidInventory, "network")
		}
		for _, address := range card.Addresses {
			if _, err := netip.ParseAddr(address); err != nil {
				return Fail(ErrInvalidInventory, "network")
			}
		}
	}
	for _, state := range []string{i.Security.DiskEncryption, i.Security.ScreenLock, i.Security.Firewall} {
		if state != "" && state != CheckOn && state != CheckOff && state != CheckUnknown {
			return Fail(ErrInvalidInventory, "security")
		}
	}
	for _, pkg := range i.Packages {
		if pkg.Kind != PackageSystem && pkg.Kind != PackageFlatpak || pkg.Name == "" ||
			!validText(pkg.Name, maxInventoryText, false) || !validText(pkg.Version, maxInventoryText, false) {
			return Fail(ErrInvalidInventory, "package")
		}
	}
	return nil
}

func (a Asset) Check() error {
	for _, text := range []string{a.Tag, a.Person, a.Location} {
		if !validText(text, maxAssetText, false) {
			return Fail(ErrInvalidAsset, text)
		}
	}
	if !validText(a.Note, maxAssetNote, true) {
		return Fail(ErrInvalidAsset, "note")
	}
	for _, date := range []string{a.Purchased, a.WarrantyUntil} {
		if _, err := time.Parse(time.DateOnly, date); date != "" && err != nil {
			return Fail(ErrInvalidAsset, date)
		}
	}
	return nil
}

// warrantyWarningDays is how long before the end the dashboard speaks up.
const warrantyWarningDays = 30

// Warning says how a warranty stands, nil if there is nothing to say. Once it is
// over there is nothing left to do about it, so that stays quiet after a while.
func (a Asset) Warning(now time.Time) *Warning {
	end, err := time.Parse(time.DateOnly, a.WarrantyUntil)
	if err != nil {
		return nil
	}
	days := int(end.Sub(now.UTC().Truncate(24*time.Hour)) / (24 * time.Hour))
	if days > warrantyWarningDays || days < -warrantyWarningDays {
		return nil
	}
	return &Warning{WarnWarrantyEnding, days}
}
