package api

import (
	"fmt"
	"strings"
)

// Error codes are the stable part of an API error: clients translate them,
// while the message stays a fallback for logs and scripts. Every code needs an
// entry in both dashboard language files, which a test enforces.
const (
	ErrMissingHeader      = "missing_header"
	ErrNotLoggedIn        = "not_logged_in"
	ErrAdminOnly          = "admin_only"
	ErrClientCertRequired = "client_cert_required"
	ErrDeviceRefused      = "device_refused"
	ErrDeviceSuspended    = "device_suspended"
	ErrInvalidAccessMode  = "invalid_access_mode"
	ErrAccessEnded        = "access_ended"
	ErrInvalidAccessImage = "invalid_access_image"
	ErrTooManyAttempts    = "too_many_attempts"
	ErrWrongCredentials   = "wrong_credentials"
	ErrWrongPassword      = "wrong_password"
	ErrEnrollTokenInvalid = "enroll_token_invalid"
	ErrInvalidCSR         = "invalid_csr"
	ErrNoSuchTask         = "no_such_task"
	ErrNoSuchDevice       = "no_such_device"
	ErrNoSuchRequest      = "no_such_request"
	ErrNoSuchUser         = "no_such_user"
	ErrUseStartPassword   = "use_start_password"
	ErrRequestDecided     = "request_decided"
	ErrInvalidUsername    = "invalid_username"
	ErrInvalidRole        = "invalid_role"
	ErrPasswordTooShort   = "password_too_short"
	ErrPasswordTooLong    = "password_too_long"
	ErrUsernameTaken      = "username_taken"
	ErrInvalidUserID      = "invalid_user_id"
	ErrLastAdmin          = "last_admin"
	ErrInternal           = "internal"
	ErrInvalidJSON        = "invalid_json"
	ErrNoPackages         = "no_packages"
	ErrInvalidPackage     = "invalid_package"
	ErrInvalidPath        = "invalid_path"
	ErrInvalidMode        = "invalid_mode"
	ErrInvalidCAName      = "invalid_ca_name"
	ErrNotPEM             = "not_pem"
	ErrInvalidUser        = "invalid_user"
	ErrSudoNoExpiry       = "sudo_no_expiry"
	ErrSudoTooLong        = "sudo_too_long"
	ErrInvalidCommand     = "invalid_command"
	ErrInvalidHash        = "invalid_hash"
	ErrInvalidFullName    = "invalid_full_name"
	ErrGroupNotAllowed    = "group_not_allowed"
	ErrNegativeLimit      = "negative_limit"
	ErrNoLimit            = "no_limit"
	ErrUnknownTaskType    = "unknown_task_type"
	ErrInvalidPayload     = "invalid_payload"
	ErrInvalidDuration    = "invalid_duration"
	ErrUnknownRequestKind = "unknown_request_kind"
	ErrInvalidKeys        = "invalid_keys"
	ErrUseAdminTool       = "use_admin_tool"
	ErrNotWaiting         = "not_waiting_for_signature"
	ErrInvalidGroupName   = "invalid_group_name"
	ErrGroupExists        = "group_exists"
	ErrNoSuchGroup        = "no_such_group"
	ErrNotForGroups       = "not_for_groups"
	ErrApproverOnly       = "approver_only"
	ErrOwnRequest         = "own_request"
	ErrDeviceNotAssigned  = "device_not_assigned"
	ErrNotForPasskey      = "not_for_passkey"
	ErrInvalidPasskey     = "invalid_passkey"
	ErrPasskeyRefused     = "passkey_refused"
	ErrPasskeyRetry       = "passkey_retry"
	ErrNoPasskeyHost      = "no_passkey_host"
	ErrPasskeyNotPinned   = "passkey_not_pinned"
)

// Messages maps every code to its English text.
var Messages = map[string]string{
	ErrMissingHeader:      "missing X-Hauswart header",
	ErrNotLoggedIn:        "not logged in",
	ErrAdminOnly:          "admin only",
	ErrClientCertRequired: "client certificate required",
	ErrDeviceRefused:      "device revoked or unknown",
	ErrDeviceSuspended:    "device is suspended in Hauswart",
	ErrInvalidAccessMode:  "access mode %s is not screen, login, fullscreen or open, or carries what it cannot use",
	ErrAccessEnded:        "the end of the block has passed",
	ErrInvalidAccessImage: "the picture must be a PNG or JPEG of at most 512 KB",
	ErrTooManyAttempts:    "too many attempts, try again in a minute",
	ErrWrongCredentials:   "wrong username or password",
	ErrWrongPassword:      "current password is wrong",
	ErrEnrollTokenInvalid: "enrollment token invalid or expired",
	ErrInvalidCSR:         "invalid CSR",
	ErrNoSuchTask:         "no such running task",
	ErrNoSuchDevice:       "no such device",
	ErrNoSuchRequest:      "no such request",
	ErrNoSuchUser:         "no such user",
	ErrUseStartPassword:   "use the start-password route",
	ErrRequestDecided:     "request was already decided",
	ErrInvalidUsername:    "invalid username",
	ErrInvalidRole:        "role must be admin, approver or member",
	ErrPasswordTooShort:   "password needs at least %s characters",
	ErrPasswordTooLong:    "password too long",
	ErrUsernameTaken:      "username already exists",
	ErrInvalidUserID:      "invalid user id",
	ErrLastAdmin:          "the last admin cannot be removed",
	ErrInternal:           "internal error",
	ErrInvalidJSON:        "invalid JSON",
	ErrNoPackages:         "no packages given",
	ErrInvalidPackage:     "invalid package name %s",
	ErrInvalidPath:        "invalid path %s",
	ErrInvalidMode:        "invalid mode %s",
	ErrInvalidCAName:      "invalid CA name %s",
	ErrNotPEM:             "not a PEM certificate",
	ErrInvalidUser:        "invalid user %s",
	ErrSudoNoExpiry:       "sudo grant needs an expiry",
	ErrSudoTooLong:        "sudo grant longer than %s",
	ErrInvalidCommand:     "invalid command %s",
	ErrInvalidHash:        "not a SHA-512 crypt hash",
	ErrInvalidFullName:    "invalid full name",
	ErrGroupNotAllowed:    "group %s not allowed",
	ErrNegativeLimit:      "limits must not be negative",
	ErrNoLimit:            "no limit given",
	ErrUnknownTaskType:    "unknown task type %s",
	ErrInvalidPayload:     "invalid payload: %s",
	ErrInvalidDuration:    "duration must be 1 to %s minutes",
	ErrUnknownRequestKind: "unknown request kind %s",
	ErrInvalidKeys:        "invalid signing keys",
	ErrUseAdminTool:       "this device is protected, use hauswart-admin",
	ErrNotWaiting:         "task is not waiting for a signature",
	ErrInvalidGroupName:   "invalid group name",
	ErrGroupExists:        "group already exists",
	ErrNoSuchGroup:        "no such group",
	ErrNotForGroups:       "%s cannot go to a whole group",
	ErrApproverOnly:       "only admins and approvers may do this",
	ErrOwnRequest:         "someone else has to decide your own request",
	ErrDeviceNotAssigned:  "this device is not assigned to you",
	ErrNotForPasskey:      "%s cannot be approved with a passkey, use hauswart-admin",
	ErrInvalidPasskey:     "invalid passkey",
	ErrPasskeyRefused:     "the passkey approval was refused",
	ErrPasskeyRetry:       "another approval went first, please approve again",
	ErrNoPasskeyHost:      "passkeys need a DNS name in the server URL, not an IP address",
	ErrPasskeyNotPinned:   "none of your passkeys is pinned on this device yet",
}

// Error is an API error. Value fills the message, for example a rejected name.
type Error struct {
	Code  string
	Value string
}

func (e *Error) Error() string {
	message := Messages[e.Code]
	if strings.Contains(message, "%s") {
		return fmt.Sprintf(message, e.Value)
	}
	return message
}

// Fail creates an Error, with an optional value for the message.
func Fail(code string, value ...string) *Error {
	return &Error{Code: code, Value: strings.Join(value, " ")}
}
