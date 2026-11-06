package api

import "maps"

// Error codes of signed actions and service certificates.
const (
	ErrInvalidDelay     = "invalid_delay"
	ErrInvalidMessage   = "invalid_message"
	ErrNoExpiry         = "no_expiry"
	ErrExpiryTooFar     = "expiry_too_far"
	ErrNoCertNames      = "no_cert_names"
	ErrInvalidCertName  = "invalid_cert_name"
	ErrCertOutsideCA    = "cert_outside_ca"
	ErrCertServerName   = "cert_server_name"
	ErrCANotConstrained = "ca_not_constrained"
	ErrInvalidCertDays  = "invalid_cert_days"

	ErrPolicyTooLarge   = "policy_too_large"
	ErrPackageProtected = "package_protected"
	ErrInvalidTimeZone  = "invalid_time_zone"
	ErrInvalidReboot    = "invalid_reboot"
	ErrInvalidWindow    = "invalid_window"
	ErrPolicyConflict   = "policy_conflict"
	ErrInvalidExtension = "invalid_extension"

	ErrManagedElsewhere = "managed_elsewhere"
	ErrOIDCFailed       = "oidc_failed"
	ErrOIDCNotAllowed   = "oidc_not_allowed"
	ErrOIDCBadName      = "oidc_bad_name"
	ErrOIDCNameTaken    = "oidc_name_taken"
	ErrInvalidDirectory = "invalid_directory"
	ErrInvalidMount     = "invalid_mount"
	ErrInvalidRequest   = "invalid_request"
	ErrSharedAccount    = "shared_account"
)

func init() {
	maps.Copy(Messages, map[string]string{
		ErrInvalidDelay:     "delay must be 1 to %s minutes",
		ErrInvalidMessage:   "message is empty, too long or has characters that are not allowed",
		ErrNoExpiry:         "task needs an expiry",
		ErrExpiryTooFar:     "expiry further away than %s",
		ErrNoCertNames:      "give 1 to %s host names",
		ErrInvalidCertName:  "invalid host name %s",
		ErrCertOutsideCA:    "%s is outside the names the CA may issue for",
		ErrCertServerName:   "%s belongs to the Hauswart server itself",
		ErrCANotConstrained: "this CA has no name constraints, so it must not issue service certificates",
		ErrInvalidCertDays:  "validity must be 1 to %s days",

		ErrPolicyTooLarge:   "policy has too many entries or is larger than %s KiB",
		ErrPackageProtected: "%s cannot be forbidden, the device depends on it",
		ErrInvalidTimeZone:  "invalid or missing time zone %s",
		ErrInvalidReboot:    "invalid reboot rule %s",
		ErrInvalidWindow:    "invalid time window %s",
		ErrPolicyConflict:   "the policy contradicts itself: %s",
		ErrInvalidExtension: "an extension needs an end at most %s from now",

		ErrManagedElsewhere: "this account is managed in Authentik",
		ErrOIDCFailed:       "the login through Authentik failed, please try again",
		ErrOIDCNotAllowed:   "this account may not use Hauswart",
		ErrOIDCBadName:      "this user name cannot be a Linux account",
		ErrOIDCNameTaken:    "a local account already has this name",
		ErrInvalidDirectory: "the directory settings are not valid: %s",
		ErrInvalidMount:     "the share is not valid: %s",
		ErrInvalidRequest:   "the request is empty, too long or has characters that are not allowed",
		ErrSharedAccount:    "several accounts use this Linux account, so please ask in the dashboard",
	})
}
