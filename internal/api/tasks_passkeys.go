package api

import (
	"maps"
	"slices"
)

// TaskPasskeyTypes sets which task types a passkey may approve on a device.
// It always needs a signature: a passkey must not widen its own reach.
const TaskPasskeyTypes = "passkeys.types"

// ErrInvalidPasskeyTypes is a list with a type outside PasskeyCapable.
const ErrInvalidPasskeyTypes = "invalid_passkey_types"

// PasskeyTypesPayload is the list. Empty means no passkey approves anything.
type PasskeyTypesPayload struct {
	Types []string `json:"types"`
}

func init() {
	register(TaskPasskeyTypes, false, checkPasskeyTypes)
	maps.Copy(Messages, map[string]string{
		ErrInvalidPasskeyTypes: "a passkey can never approve %s",
	})
}

func checkPasskeyTypes(p PasskeyTypesPayload) error {
	if p.Types == nil {
		return Fail(ErrInvalidPasskeyTypes, "a missing list")
	}
	for i, t := range p.Types {
		if !PasskeyEligible(t) || slices.Contains(p.Types[:i], t) {
			return Fail(ErrInvalidPasskeyTypes, t)
		}
	}
	return nil
}

// SortedTypes is a list of types in a fixed order, for comparing and signing.
func SortedTypes(types []string) []string {
	sorted := slices.Clone(types)
	slices.Sort(sorted)
	return slices.Compact(sorted)
}
