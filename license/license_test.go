package license_test

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/shikejing/offline-license-verification-go/license"
)

// fakeClock is a manually controlled clock for deterministic tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

const machineA = "machine-fingerprint-A"

func newTestEnv(t *testing.T) (*license.Issuer, *license.Verifier, *fakeClock) {
	t.Helper()
	pub, priv, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	clk := &fakeClock{t: time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)}
	dir := t.TempDir()
	v, err := license.NewVerifier(pub, filepath.Join(dir, "license-state.json"),
		license.WithClock(clk),
		license.WithFingerprint(func() (string, error) { return machineA, nil }),
		license.WithRollbackGrace(time.Minute),
		license.WithForwardJumpLimit(24*time.Hour),
	)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	iss := license.NewIssuer(priv, "test-issuer")
	return iss, v, clk
}

func issueAt(iss *license.Issuer, fp string, issuedAt, expiresAt time.Time, scope ...string) (string, string) {
	id := fmt.Sprintf("lic-%s-%d", fp, issuedAt.Unix())
	tok, err := iss.Issue(license.Claims{
		ID:        id,
		Issuer:    "test-issuer",
		IssuedAt:  issuedAt,
		NotBefore: issuedAt,
		ExpiresAt: expiresAt,
		Scope:     scope,
		MachineID: fp,
	})
	if err != nil {
		panic(err)
	}
	return tok, id
}

func TestValidLicense(t *testing.T) {
	iss, v, clk := newTestEnv(t)
	tok, _ := issueAt(iss, machineA, clk.Now(), clk.Now().Add(time.Hour), "read", "write")

	res, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.Valid || res.Reason != license.ReasonOK {
		t.Fatalf("expected valid, got %s: %s", res.Reason, res.Message)
	}
	if res.License == nil || res.License.MachineID != machineA {
		t.Fatalf("license binding mismatch: %+v", res.License)
	}
	if !res.License.HasScope("read") || !res.License.HasScope("write") {
		t.Fatalf("scope not carried: %v", res.License.Scope)
	}
	if res.CheckedAt.IsZero() || res.MachineID != machineA {
		t.Fatalf("result trace fields missing: %+v", res)
	}
}

func TestMachineMismatch(t *testing.T) {
	iss, v, clk := newTestEnv(t)
	tok, _ := issueAt(iss, "machine-fingerprint-B", clk.Now(), clk.Now().Add(time.Hour))

	res, err := v.Verify(tok)
	if !errors.Is(err, license.ErrMachineMismatch) {
		t.Fatalf("expected ErrMachineMismatch, got %v", err)
	}
	if res.Valid || res.Reason != license.ReasonMachineMismatch {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestExpiry(t *testing.T) {
	iss, v, clk := newTestEnv(t)
	tok, _ := issueAt(iss, machineA, clk.Now(), clk.Now().Add(time.Hour))

	if _, err := v.Verify(tok); err != nil {
		t.Fatalf("before expiry: %v", err)
	}
	clk.add(2 * time.Hour)
	res, err := v.Verify(tok)
	if !errors.Is(err, license.ErrExpired) {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
	if res.Reason != license.ReasonExpired {
		t.Fatalf("unexpected reason: %s", res.Reason)
	}
}

func TestNotYetValid(t *testing.T) {
	iss, v, clk := newTestEnv(t)
	tok, _ := issueAt(iss, machineA, clk.Now().Add(time.Hour), clk.Now().Add(2*time.Hour))

	res, err := v.Verify(tok)
	if !errors.Is(err, license.ErrNotYetValid) {
		t.Fatalf("expected ErrNotYetValid, got %v", err)
	}
	if res.Reason != license.ReasonNotYetValid {
		t.Fatalf("unexpected reason: %s", res.Reason)
	}
}

func TestClockRollback(t *testing.T) {
	iss, v, clk := newTestEnv(t)
	t0 := clk.Now()
	// License started an hour ago, so small clock drift stays inside the
	// validity window.
	tok, _ := issueAt(iss, machineA, t0.Add(-time.Hour), t0.Add(10*time.Hour))

	if _, err := v.Verify(tok); err != nil {
		t.Fatalf("initial verify: %v", err)
	}

	// Roll back within the grace period: tolerated.
	clk.add(-30 * time.Second)
	if _, err := v.Verify(tok); err != nil {
		t.Fatalf("rollback within grace should be tolerated: %v", err)
	}

	// Roll back beyond the grace period: rejected.
	clk.add(-10 * time.Minute)
	res, err := v.Verify(tok)
	if !errors.Is(err, license.ErrClockRollback) {
		t.Fatalf("expected ErrClockRollback, got %v", err)
	}
	if res.Reason != license.ReasonClockRollback {
		t.Fatalf("unexpected reason: %s", res.Reason)
	}
}

func TestExpiredLicenseCannotBeResurrectedByRollback(t *testing.T) {
	iss, v, clk := newTestEnv(t)
	t0 := clk.Now()
	tok, _ := issueAt(iss, machineA, t0, t0.Add(time.Hour))

	// Move past expiry: license is expired, but the HWM is advanced.
	clk.add(2 * time.Hour)
	if _, err := v.Verify(tok); !errors.Is(err, license.ErrExpired) {
		t.Fatalf("expected expired, got %v", err)
	}

	// Roll back into the original validity window: must still fail because
	// the persisted high-water mark is at t0+2h.
	clk.set(t0.Add(30 * time.Minute))
	res, err := v.Verify(tok)
	if !errors.Is(err, license.ErrClockRollback) {
		t.Fatalf("rollback into validity window must be rejected, got %v", err)
	}
	if res.Reason != license.ReasonClockRollback {
		t.Fatalf("unexpected reason: %s", res.Reason)
	}
}

func TestClockForwardJump(t *testing.T) {
	iss, v, clk := newTestEnv(t)
	tok, _ := issueAt(iss, machineA, clk.Now(), clk.Now().Add(100*time.Hour))

	if _, err := v.Verify(tok); err != nil {
		t.Fatalf("initial verify: %v", err)
	}
	clk.add(25 * time.Hour) // beyond the 24h limit
	res, err := v.Verify(tok)
	if !errors.Is(err, license.ErrClockForwardJump) {
		t.Fatalf("expected ErrClockForwardJump, got %v", err)
	}
	if res.Reason != license.ReasonClockForwardJump {
		t.Fatalf("unexpected reason: %s", res.Reason)
	}
}

func TestForwardJumpDoesNotPoisonHighWaterMark(t *testing.T) {
	iss, v, clk := newTestEnv(t)
	t0 := clk.Now()
	tok, _ := issueAt(iss, machineA, t0, t0.Add(100*time.Hour))

	if _, err := v.Verify(tok); err != nil {
		t.Fatalf("initial verify: %v", err)
	}
	// Forward jump is rejected and must NOT be adopted as the high-water
	// mark, so a normal observation afterwards still verifies.
	clk.add(25 * time.Hour)
	if _, err := v.Verify(tok); !errors.Is(err, license.ErrClockForwardJump) {
		t.Fatalf("expected forward jump rejection, got %v", err)
	}
	clk.set(t0.Add(time.Hour))
	if _, err := v.Verify(tok); err != nil {
		t.Fatalf("normal time after rejected jump should verify, got %v", err)
	}
}

func TestTamperedToken(t *testing.T) {
	iss, v, clk := newTestEnv(t)
	tok, _ := issueAt(iss, machineA, clk.Now(), clk.Now().Add(time.Hour))

	parts := splitToken(tok)

	cases := []struct {
		name  string
		token string
	}{
		{"payload modified", parts[0] + "." + flipChar(parts[1]) + "." + parts[2]},
		{"signature modified", parts[0] + "." + parts[1] + "." + flipChar(parts[2])},
		{"truncated", parts[0] + "." + parts[1]},
		{"garbage", "not-a-license-token"},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := v.Verify(tc.token)
			if err == nil {
				t.Fatalf("expected failure for %s", tc.name)
			}
			if res.Valid {
				t.Fatalf("token must not validate: %s", tc.name)
			}
			if !errors.Is(err, license.ErrInvalidSignature) && !errors.Is(err, license.ErrMalformed) {
				t.Fatalf("expected tamper/malformed error, got %v", err)
			}
		})
	}
}

func TestWrongKey(t *testing.T) {
	_, v, clk := newTestEnv(t)
	otherPub, otherPriv, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_ = otherPub
	otherIss := license.NewIssuer(otherPriv, "other")
	tok, _ := issueAt(otherIss, machineA, clk.Now(), clk.Now().Add(time.Hour))

	_, err = v.Verify(tok)
	if !errors.Is(err, license.ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for wrong key, got %v", err)
	}
}

func TestScopeEnforcement(t *testing.T) {
	iss, v, clk := newTestEnv(t)
	tok, _ := issueAt(iss, machineA, clk.Now(), clk.Now().Add(time.Hour), "read")

	if _, err := v.VerifyScope(tok, "read"); err != nil {
		t.Fatalf("read should be granted: %v", err)
	}
	res, err := v.VerifyScope(tok, "write")
	if !errors.Is(err, license.ErrScopeNotGranted) {
		t.Fatalf("expected ErrScopeNotGranted, got %v", err)
	}
	if res.Reason != license.ReasonScopeNotGranted {
		t.Fatalf("unexpected reason: %s", res.Reason)
	}
}

func TestRevocation(t *testing.T) {
	iss, v, clk := newTestEnv(t)
	tok, id := issueAt(iss, machineA, clk.Now(), clk.Now().Add(time.Hour))

	if _, err := v.Verify(tok); err != nil {
		t.Fatalf("before revoke: %v", err)
	}
	if err := v.Revoke(id, "terms of service violation"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, ok := v.RevokedAt(id); !ok {
		t.Fatal("revocation not recorded")
	}
	res, err := v.Verify(tok)
	if !errors.Is(err, license.ErrRevoked) {
		t.Fatalf("expected ErrRevoked, got %v", err)
	}
	if res.Reason != license.ReasonRevoked || res.RevokedAt.IsZero() {
		t.Fatalf("revocation trace missing: %+v", res)
	}
}

func TestRevocationSurvivesRestart(t *testing.T) {
	pub, priv, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	clk := &fakeClock{t: time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)}
	statePath := filepath.Join(t.TempDir(), "license-state.json")
	iss := license.NewIssuer(priv, "test-issuer")

	v1, err := license.NewVerifier(pub, statePath,
		license.WithClock(clk),
		license.WithFingerprint(func() (string, error) { return machineA, nil }),
		license.WithRollbackGrace(time.Minute),
		license.WithForwardJumpLimit(24*time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	tok, id := issueAt(iss, machineA, clk.Now(), clk.Now().Add(time.Hour))
	if _, err := v1.Verify(tok); err != nil {
		t.Fatalf("before revoke: %v", err)
	}
	if err := v1.Revoke(id, "restart test"); err != nil {
		t.Fatal(err)
	}

	// Simulate process restart: brand new verifier instance on the same
	// state file.
	v2, err := license.NewVerifier(pub, statePath,
		license.WithClock(clk),
		license.WithFingerprint(func() (string, error) { return machineA, nil }),
		license.WithRollbackGrace(time.Minute),
		license.WithForwardJumpLimit(24*time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := v2.RevokedAt(id); !ok {
		t.Fatal("revocation did not survive restart")
	}
	if _, err := v2.Verify(tok); !errors.Is(err, license.ErrRevoked) {
		t.Fatalf("revocation must persist across restart, got %v", err)
	}
}

func TestHighWaterMarkSurvivesRestart(t *testing.T) {
	pub, priv, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	clk := &fakeClock{t: time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)}
	statePath := filepath.Join(t.TempDir(), "license-state.json")
	iss := license.NewIssuer(priv, "test-issuer")
	tok, _ := issueAt(iss, machineA, clk.Now(), clk.Now().Add(100*time.Hour))

	opts := []license.Option{
		license.WithClock(clk),
		license.WithFingerprint(func() (string, error) { return machineA, nil }),
		license.WithRollbackGrace(time.Minute),
		license.WithForwardJumpLimit(24 * time.Hour),
	}
	v1, err := license.NewVerifier(pub, statePath, opts...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v1.Verify(tok); err != nil {
		t.Fatal(err)
	}
	clk.add(2 * time.Hour)
	if _, err := v1.Verify(tok); err != nil {
		t.Fatal(err)
	}

	// Restart with a new instance; rollback must still be detected via the
	// persisted high-water mark.
	v2, err := license.NewVerifier(pub, statePath, opts...)
	if err != nil {
		t.Fatal(err)
	}
	clk.add(-30 * time.Second) // within grace, still fine
	if _, err := v2.Verify(tok); err != nil {
		t.Fatalf("within grace after restart: %v", err)
	}
	clk.add(-10 * time.Minute) // beyond grace
	if _, err := v2.Verify(tok); !errors.Is(err, license.ErrClockRollback) {
		t.Fatalf("rollback after restart must be detected, got %v", err)
	}
}

func TestConcurrentVerification(t *testing.T) {
	iss, v, clk := newTestEnv(t)
	tok, _ := issueAt(iss, machineA, clk.Now(), clk.Now().Add(time.Hour))

	const n = 50
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, err := v.Verify(tok)
			if err != nil || !res.Valid || res.Reason != license.ReasonOK {
				errs[i] = fmt.Errorf("err=%v reason=%s", err, res.Reason)
			}
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Fatalf("goroutine %d: %v", i, e)
		}
	}
}

func TestConcurrentRevokeAndVerify(t *testing.T) {
	iss, v, clk := newTestEnv(t)
	tok, id := issueAt(iss, machineA, clk.Now(), clk.Now().Add(time.Hour))

	const n = 40
	var wg sync.WaitGroup
	results := make([]license.Reason, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, _ := v.Verify(tok)
			results[i] = res.Reason
		}(i)
	}
	// Revoke concurrently with the verifications.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = v.Revoke(id, "concurrent test")
	}()
	wg.Wait()

	// Every result must be a known, deterministic outcome.
	seen := map[license.Reason]int{}
	for _, r := range results {
		if r != license.ReasonOK && r != license.ReasonRevoked {
			t.Fatalf("unexpected outcome in concurrent run: %s", r)
		}
		seen[r]++
	}
	// After Revoke returns, revocation is durable and every subsequent
	// verification must be revoked.
	if _, err := v.Verify(tok); !errors.Is(err, license.ErrRevoked) {
		t.Fatalf("after revoke completed, expected ErrRevoked, got %v", err)
	}
	t.Logf("concurrent outcomes: %v", seen)
}

func TestIssuerDefaults(t *testing.T) {
	pub, priv, err := license.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	iss := license.NewIssuer(priv, "default-issuer")
	tok, err := iss.Issue(license.Claims{MachineID: machineA})
	if err != nil {
		t.Fatal(err)
	}
	clk := &fakeClock{t: time.Now()}
	v, err := license.NewVerifier(pub, filepath.Join(t.TempDir(), "s.json"),
		license.WithClock(clk),
		license.WithFingerprint(func() (string, error) { return machineA, nil }),
	)
	if err != nil {
		t.Fatal(err)
	}
	res, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("default license should be valid for 1 year: %v", err)
	}
	if res.License.ID == "" || res.License.Issuer != "default-issuer" {
		t.Fatalf("defaults not applied: %+v", res.License)
	}
}

// splitToken splits "LIC1.payload.sig" into its three parts.
func splitToken(tok string) []string {
	parts := make([]string, 0, 3)
	start := 0
	for i := 0; i < len(tok); i++ {
		if tok[i] == '.' {
			parts = append(parts, tok[start:i])
			start = i + 1
		}
	}
	parts = append(parts, tok[start:])
	return parts
}

// flipChar replaces one character with a different letter.
func flipChar(s string) string {
	b := []byte(s)
	if len(b) == 0 {
		return s
	}
	if b[0] == 'A' {
		b[0] = 'B'
	} else {
		b[0] = 'A'
	}
	return string(b)
}
