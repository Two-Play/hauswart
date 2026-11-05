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
	})
}
