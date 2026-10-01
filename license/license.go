// Package license implements offline software license issuance and verification.
//
// Licenses are signed with Ed25519 by an in-process issuer and verified locally
// without any network access. Verification is bound to a machine fingerprint,
// detects clock rollback / forward jumps via a persisted high-water mark, and
// honors a persisted revocation list.
package license

import (
	"errors"
	"time"
)

// TokenPrefix is the human-readable prefix of every license token.
const TokenPrefix = "LIC1"

// Reason is a machine-readable verification outcome.
type Reason string

const (
	ReasonOK               Reason = "ok"
	ReasonMalformed        Reason = "malformed"
	ReasonInvalidSignature Reason = "invalid_signature"
	ReasonExpired          Reason = "expired"
	ReasonNotYetValid      Reason = "not_yet_valid"
	ReasonMachineMismatch  Reason = "machine_mismatch"
	ReasonRevoked          Reason = "revoked"
	ReasonClockRollback    Reason = "clock_rollback"
	ReasonClockForwardJump Reason = "clock_forward_jump"
	ReasonScopeNotGranted  Reason = "scope_not_granted"
	ReasonInternal         Reason = "internal_error"
)

// Distinguishable verification failures. Use errors.Is to test for them.
var (
	ErrMalformed        = errors.New("license: malformed token")
	ErrInvalidSignature = errors.New("license: invalid signature or tampered payload")
	ErrExpired          = errors.New("license: license has expired")
	ErrNotYetValid      = errors.New("license: license is not valid yet")
	ErrMachineMismatch  = errors.New("license: machine fingerprint mismatch")
	ErrRevoked          = errors.New("license: license has been revoked")
	ErrClockRollback    = errors.New("license: clock rollback beyond grace period")
	ErrClockForwardJump = errors.New("license: clock forward jump beyond limit")
	ErrScopeNotGranted  = errors.New("license: required scope not granted")
)

// Claims is the set of claims carried by a license.
type Claims struct {
	// ID is the unique license identifier (jti), used for revocation.
	ID string
	// Issuer identifies the issuer of the license.
	Issuer string
	// IssuedAt is the issuance time.
	IssuedAt time.Time
	// NotBefore is the earliest time at which the license is valid.
	NotBefore time.Time
	// ExpiresAt is the expiry time.
	ExpiresAt time.Time
	// Scope is the authorized scope (e.g. feature names / permissions).
	Scope []string
	// MachineID is the fingerprint of the machine the license is bound to.
	MachineID string
}

// License is a verified license. It embeds the signed claims.
type License struct {
	Claims
}

// Result describes the outcome of a verification attempt.
type Result struct {
	// Valid reports whether the license is valid.
	Valid bool
	// Reason is the machine-readable outcome code.
	Reason Reason
	// Message is a human-readable trace message.
	Message string
	// License is the verified license (nil when verification failed).
	License *License
	// CheckedAt is the time at which verification ran.
	CheckedAt time.Time
	// MachineID is the fingerprint of the verifying machine.
	MachineID string
	// RevokedAt is the revocation time when Reason == ReasonRevoked.
	RevokedAt time.Time
}

// HasScope reports whether the license grants the given scope.
func (l *License) HasScope(scope string) bool {
	for _, s := range l.Scope {
		if s == scope {
			return true
		}
	}
	return false
}
