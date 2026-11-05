package api

import "encoding/json"

// taskSpec is what the system knows about a task type. Each feature registers
// its types from its own file, so adding one does not touch the others.
type taskSpec struct {
	validate func(json.RawMessage) error
	unsigned bool
}

var specs = map[string]taskSpec{}

// Unsigned marks a task type that a protected device runs without a signature.
// Use it only for types that cannot gain anyone anything.
type Unsigned bool

// register adds a task type with a typed check. A payload with unknown fields
// never reaches the check.
func register[T any](taskType string, unsigned Unsigned, check func(T) error) {
	specs[taskType] = taskSpec{
		unsigned: bool(unsigned),
		validate: func(raw json.RawMessage) error {
			var payload T
			if err := strictDecode(raw, &payload); err != nil {
				return err
			}
			return check(payload)
		},
	}
}

// Validate checks a task payload without touching the system.
func Validate(taskType string, payload json.RawMessage) error {
	spec, ok := specs[taskType]
	if !ok {
		return Fail(ErrUnknownTaskType, taskType)
	}
	return spec.validate(payload)
}

// NeedsSignature says whether a task requires a signature on a protected
// device. Unknown types do.
func NeedsSignature(taskType string) bool {
	return !specs[taskType].unsigned
}
