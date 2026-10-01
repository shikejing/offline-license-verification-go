package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// payloadVersion is the current claims payload format version.
const payloadVersion = 1

// claimsPayload is the canonical JSON payload that gets signed. Field order
// is fixed so the signed bytes are deterministic.
type claimsPayload struct {
	Version   int      `json:"v"`
	ID        string   `json:"jti"`
	Issuer    string   `json:"iss,omitempty"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf"`
	ExpiresAt int64    `json:"exp"`
	Scope     []string `json:"scope,omitempty"`
	MachineID string   `json:"mid"`
}

// encodeToken serializes the claims and returns "LIC1.<payload>.<sig>".
// The signature covers the exact payload bytes, so any post-issuance
// modification invalidates the token.
func encodeToken(c Claims, priv ed25519.PrivateKey) (string, error) {
	p := claimsPayload{
		Version:   payloadVersion,
		ID:        c.ID,
		Issuer:    c.Issuer,
		IssuedAt:  c.IssuedAt.Unix(),
		NotBefore: c.NotBefore.Unix(),
		ExpiresAt: c.ExpiresAt.Unix(),
		Scope:     c.Scope,
		MachineID: c.MachineID,
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, raw)
	return TokenPrefix + "." +
		base64.RawURLEncoding.EncodeToString(raw) + "." +
		base64.RawURLEncoding.EncodeToString(sig), nil
}

// decodeAndVerify parses a token, verifies its signature against the given
// public key, and returns the embedded license. Malformed tokens yield
// ErrMalformed; tokens with a bad signature or altered payload yield
// ErrInvalidSignature.
func decodeAndVerify(tokenStr string, pub ed25519.PublicKey) (*License, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 || parts[0] != TokenPrefix {
		return nil, ErrMalformed
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrMalformed
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, ErrMalformed
	}
	if !ed25519.Verify(pub, raw, sig) {
		return nil, ErrInvalidSignature
	}

	var p claimsPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, ErrMalformed
	}
	if p.Version != payloadVersion {
		return nil, ErrMalformed
	}
	if p.ID == "" || p.MachineID == "" || p.ExpiresAt == 0 {
		return nil, ErrMalformed
	}

	return &License{Claims: Claims{
		ID:        p.ID,
		Issuer:    p.Issuer,
		IssuedAt:  time.Unix(p.IssuedAt, 0),
		NotBefore: time.Unix(p.NotBefore, 0),
		ExpiresAt: time.Unix(p.ExpiresAt, 0),
		Scope:     p.Scope,
		MachineID: p.MachineID,
	}}, nil
}

// newLicenseID generates a random, unique license id (jti).
func newLicenseID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
