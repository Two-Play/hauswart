package api

import "time"

// Insight is the read-only view of a device that goes into every report.
type Insight struct {
	// CertExpires comes from the certificate the device connected with. The
	// server fills it in, so a device cannot claim anything else.
	CertExpires *time.Time    `json:"cert_expires,omitempty"`
	Accounts    []Account     `json:"accounts,omitempty"`
	Updates     *UpdateStatus `json:"updates,omitempty"`
	// InventoryAt says how fresh the inventory is, which changes less often than
	// it is taken.
	InventoryAt *time.Time `json:"inventory_at,omitempty"`
}

// Account is one login account of a device, with UID 1000 or above.
type Account struct {
	Name   string   `json:"name"`
	UID    int      `json:"uid"`
	Groups []string `json:"groups"`
	// Privileged lists the groups that amount to root.
	Privileged []string `json:"privileged,omitempty"`
	// Sudo holds the rules as sudo itself lists them, including those from
	// group membership. SudoUnknown says that sudo could not tell.
	Sudo        []string `json:"sudo,omitempty"`
	SudoUnknown bool     `json:"sudo_unknown,omitempty"`
	// GrantExpires is set while a temporary grant from Hauswart runs.
	GrantExpires *time.Time `json:"grant_expires,omitempty"`
}

// The possible values of UpdateStatus.Reboot.
const (
	RebootRequired    = "required"
	RebootNotRequired = "not_required"
	RebootUnknown     = "unknown"
)

// UpdateStatus is the result of the last update check on a device.
type UpdateStatus struct {
	// CheckedAt is the last successful check. Pending and Packages stay from
	// that check if a later one fails, and Error then says why.
	CheckedAt *time.Time `json:"checked_at,omitempty"`
	Pending   int        `json:"pending"`
	// Packages is cut off after MaxUpdateNames, Pending is not.
	Packages []string `json:"packages,omitempty"`
	Reboot   string   `json:"reboot"`
	Error    string   `json:"error,omitempty"`
}

// MaxUpdateNames limits the package names in a report.
const MaxUpdateNames = 100

// PrivilegedGroup says whether membership in a group equals root.
func PrivilegedGroup(name string) bool { return privilegedGroups[name] }

// Warning is something an admin should look at. Value depends on the code.
type Warning struct {
	Code  string `json:"code"`
	Value int    `json:"value"`
}

const (
	// WarnDiskFull carries the used percentage.
	WarnDiskFull = "disk_full"
	// WarnCertExpiring carries the days left, which are negative once the
	// certificate has expired.
	WarnCertExpiring = "cert_expiring"
	// WarnWarrantyEnding carries the days left, which are negative once it ended.
	WarnWarrantyEnding = "warranty_ending"

	diskFullPercent = 90
	// Agents renew long before this, so a device that gets here is either
	// switched off or has a problem with renewal.
	certExpiringWithin = 30 * 24 * time.Hour
)

// Warnings evaluates a report at a given time, so that a device that went
// quiet still shows its certificate running out.
func (r *Report) Warnings(now time.Time) []Warning {
	var warnings []Warning
	if r.DiskTotal > 0 {
		if percent := int(float64(r.DiskUsed) / float64(r.DiskTotal) * 100); percent >= diskFullPercent {
			warnings = append(warnings, Warning{WarnDiskFull, percent})
		}
	}
	if r.CertExpires != nil {
		if left := r.CertExpires.Sub(now); left < certExpiringWithin {
			warnings = append(warnings, Warning{WarnCertExpiring, int(left / (24 * time.Hour))})
		}
	}
	return warnings
}
