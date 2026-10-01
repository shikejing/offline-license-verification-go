package license

import (
	"crypto/ed25519"
	"time"
)

// DefaultValidity is used when Claims.ExpiresAt is left zero.
const DefaultValidity = 365 * 24 * time.Hour

// Issuer creates signed license tokens using an Ed25519 private key.
type Issuer struct {
	priv   ed25519.PrivateKey
	issuer string
	clock  Clock
}

// GenerateKeyPair generates a new Ed25519 key pair for signing/verification.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

// NewIssuer creates an issuer backed by the given private key.
// issuer is an optional label written into the "iss" claim.
func NewIssuer(priv ed25519.PrivateKey, issuer string) *Issuer {
	return &Issuer{priv: priv, issuer: issuer, clock: realClock{}}
}

// Issue signs and returns a new license token for the given claims.
// Zero fields are filled with defaults: a random ID, the current time for
// IssuedAt/NotBefore, and a 1-year validity window when ExpiresAt is zero.
// MachineID must be set to the target machine's fingerprint.
func (i *Issuer) Issue(c Claims) (string, error) {
	now := i.clock.Now()
	if c.ID == "" {
		id, err := newLicenseID()
		if err != nil {
			return "", err
		}
		c.ID = id
	}
	if c.Issuer == "" {
		c.Issuer = i.issuer
	}
	if c.IssuedAt.IsZero() {
		c.IssuedAt = now
	}
	if c.NotBefore.IsZero() {
		c.NotBefore = c.IssuedAt
	}
	if c.ExpiresAt.IsZero() {
		c.ExpiresAt = c.IssuedAt.Add(DefaultValidity)
	}
	return encodeToken(c, i.priv)
}
