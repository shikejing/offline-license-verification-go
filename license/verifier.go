package license

import (
	"crypto/ed25519"
	"crypto/subtle"
	"sync"
	"time"
)

// Default clock-policy parameters.
const (
	// DefaultRollbackGrace is how far the clock may move backwards without
	// being treated as a rollback attack.
	DefaultRollbackGrace = 5 * time.Minute
	// DefaultForwardJumpLimit is how far the clock may jump forwards without
	// being treated as an anomaly.
	DefaultForwardJumpLimit = 30 * 24 * time.Hour
)

// Verifier validates license tokens against a machine fingerprint and a
// persisted state file holding the revocation list and the clock
// high-water mark. All operations are safe for concurrent use.
type Verifier struct {
	pub              ed25519.PublicKey
	mu               sync.Mutex
	store            *stateStore
	state            persistedState
	clock            Clock
	fingerprint      FingerprintFunc
	rollbackGrace    time.Duration
	forwardJumpLimit time.Duration
}

// Option configures a Verifier.
type Option func(*Verifier)

// WithClock overrides the time source (intended for tests).
func WithClock(c Clock) Option {
	return func(v *Verifier) { v.clock = c }
}

// WithFingerprint overrides the machine fingerprint source.
func WithFingerprint(f FingerprintFunc) Option {
	return func(v *Verifier) { v.fingerprint = f }
}

// WithRollbackGrace sets the tolerated backwards clock drift.
func WithRollbackGrace(d time.Duration) Option {
	return func(v *Verifier) { v.rollbackGrace = d }
}

// WithForwardJumpLimit sets the tolerated forwards clock jump.
func WithForwardJumpLimit(d time.Duration) Option {
	return func(v *Verifier) { v.forwardJumpLimit = d }
}

// NewVerifier creates a verifier for the given public key. statePath points
// to the persisted state file (revocation list + clock high-water mark);
// it is created on first use if it does not exist.
func NewVerifier(pub ed25519.PublicKey, statePath string, opts ...Option) (*Verifier, error) {
	v := &Verifier{
		pub:              pub,
		store:            newStateStore(statePath),
		clock:            realClock{},
		rollbackGrace:    DefaultRollbackGrace,
		forwardJumpLimit: DefaultForwardJumpLimit,
	}
	for _, opt := range opts {
		opt(v)
	}
	if v.fingerprint == nil {
		v.fingerprint = MachineFingerprint
	}
	st, err := v.store.load()
	if err != nil {
		return nil, err
	}
	v.state = st
	return v, nil
}

// Verify checks a license token against the current machine fingerprint and
// the persisted clock/revocation state. The returned error is one of the
// sentinel errors when the license is invalid, or nil when it is valid.
// Infrastructure errors (e.g. fingerprint or persistence failures) are
// returned as errors without a sentinel.
//
// Checks run in this deterministic order: signature/tamper, machine
// binding, clock rollback, clock forward jump, not-before, expiry,
// revocation, scope. The clock high-water mark is advanced monotonically
// and atomically persisted for every observation that passes the clock
// sanity checks, so rolling the clock back into a previously valid window
// cannot resurrect an expired license.
func (v *Verifier) Verify(tokenStr string) (*Result, error) {
	return v.verify(tokenStr, "")
}

// VerifyScope is like Verify but also requires the license to grant the
// given scope.
func (v *Verifier) VerifyScope(tokenStr, scope string) (*Result, error) {
	return v.verify(tokenStr, scope)
}

func (v *Verifier) verify(tokenStr, requiredScope string) (*Result, error) {
	now := v.clock.Now()

	fp, err := v.fingerprint()
	if err != nil {
		return &Result{Valid: false, Reason: ReasonInternal, Message: err.Error(), CheckedAt: now}, err
	}

	// 1. Signature / tamper check (no state needed).
	lic, err := decodeAndVerify(tokenStr, v.pub)
	if err != nil {
		reason := ReasonMalformed
		if err == ErrInvalidSignature {
			reason = ReasonInvalidSignature
		}
		return &Result{
			Valid: false, Reason: reason, Message: err.Error(),
			CheckedAt: now, MachineID: fp,
		}, err
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	// 2. Machine binding (constant-time comparison).
	if subtle.ConstantTimeCompare([]byte(lic.MachineID), []byte(fp)) != 1 {
		return v.reject(ReasonMachineMismatch, lic, now, fp,
			"license is bound to another machine"), ErrMachineMismatch
	}

	// 3. Clock policy against the persisted high-water mark.
	if v.state.LastSeen != 0 {
		delta := now.Unix() - v.state.LastSeen
		if delta < -int64(v.rollbackGrace/time.Second) {
			return v.reject(ReasonClockRollback, lic, now, fp,
				"clock moved backwards beyond grace period"), ErrClockRollback
		}
		if delta > int64(v.forwardJumpLimit/time.Second) {
			return v.reject(ReasonClockForwardJump, lic, now, fp,
				"clock jumped forwards beyond limit"), ErrClockForwardJump
		}
	}

	// Clock sanity passed: advance the high-water mark monotonically and
	// persist it BEFORE the license-level checks. This is crucial: an
	// expired/revoked license verified at a plausible time must still record
	// the observation, otherwise rolling the clock back into a previously
	// valid window would resurrect the license.
	if now.Unix() > v.state.LastSeen {
		v.state.LastSeen = now.Unix()
		if err := v.store.persist(v.state); err != nil {
			return &Result{
				Valid: false, Reason: ReasonInternal, License: lic,
				CheckedAt: now, MachineID: fp,
				Message: "failed to persist clock state: " + err.Error(),
			}, err
		}
	}

	// 4. Not-before.
	if now.Before(lic.NotBefore) {
		return v.reject(ReasonNotYetValid, lic, now, fp,
			"license is not valid yet"), ErrNotYetValid
	}

	// 5. Expiry.
	if !now.Before(lic.ExpiresAt) {
		return v.reject(ReasonExpired, lic, now, fp,
			"license has expired"), ErrExpired
	}

	// 6. Revocation.
	if rec, ok := v.state.Revoked[lic.ID]; ok {
		res := v.reject(ReasonRevoked, lic, now, fp,
			"license has been revoked: "+rec.Reason)
		res.RevokedAt = time.Unix(rec.At, 0)
		return res, ErrRevoked
	}

	// 7. Scope.
	if requiredScope != "" && !lic.HasScope(requiredScope) {
		return v.reject(ReasonScopeNotGranted, lic, now, fp,
			"license does not grant scope "+requiredScope), ErrScopeNotGranted
	}

	return &Result{
		Valid: true, Reason: ReasonOK, License: lic,
		CheckedAt: now, MachineID: fp,
		Message: "license valid",
	}, nil
}

// reject builds a failed result.
func (v *Verifier) reject(r Reason, lic *License, now time.Time, fp, msg string) *Result {
	return &Result{
		Valid: false, Reason: r, Message: msg, License: lic,
		CheckedAt: now, MachineID: fp,
	}
}

// Revoke adds the license with the given ID to the persisted revocation
// list. Revocation survives process restarts.
func (v *Verifier) Revoke(id, reason string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.state.Revoked[id] = revokedRecord{At: v.clock.Now().Unix(), Reason: reason}
	return v.store.persist(v.state)
}

// RevokedAt returns the revocation time for a revoked license id and whether
// it is revoked.
func (v *Verifier) RevokedAt(id string) (time.Time, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()

	rec, ok := v.state.Revoked[id]
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(rec.At, 0), true
}

// LastSeen returns the persisted clock high-water mark.
func (v *Verifier) LastSeen() time.Time {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.state.LastSeen == 0 {
		return time.Time{}
	}
	return time.Unix(v.state.LastSeen, 0)
}
