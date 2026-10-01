package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// IssueRequest 描述一次签发。
type IssueRequest struct {
	Subject   string
	Scope     []string
	NotBefore time.Time
	ExpiresAt time.Time
	Machine   Fingerprint
}

// Issuer 在本地进程内签发凭证。
type Issuer struct {
	priv ed25519.PrivateKey
	now  func() time.Time
}

// NewIssuer 以私钥创建签发者。
func NewIssuer(priv ed25519.PrivateKey) *Issuer {
	return &Issuer{priv: priv, now: time.Now}
}

// SetClock 注入时间来源（测试用）。
func (i *Issuer) SetClock(now func() time.Time) { i.now = now }

// GenerateKey 生成一对 Ed25519 密钥。
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// Issue 签发一张绑定机器的凭证。
func (i *Issuer) Issue(req IssueRequest) (string, error) {
	if len(i.priv) != ed25519.PrivateKeySize {
		return "", errors.New("issuer: invalid private key")
	}
	if req.ExpiresAt.IsZero() {
		return "", errors.New("issuer: ExpiresAt is required")
	}
	if !req.NotBefore.IsZero() && !req.ExpiresAt.After(req.NotBefore) {
		return "", errors.New("issuer: ExpiresAt must be after NotBefore")
	}
	nb := req.NotBefore
	if nb.IsZero() {
		nb = i.now()
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("issuer: generate nonce: %w", err)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "", fmt.Errorf("issuer: generate id: %w", err)
	}
	scope := append([]string(nil), req.Scope...)
	if scope == nil {
		scope = []string{}
	}
	p := &Payload{
		ID:          hex.EncodeToString(id),
		Subject:     req.Subject,
		Scope:       scope,
		IssuedAt:    i.now().UTC(),
		NotBefore:   nb.UTC(),
		ExpiresAt:   req.ExpiresAt.UTC(),
		MachineHash: req.Machine.Hash(),
		Nonce:       hex.EncodeToString(nonce),
	}
	body, err := p.canonical()
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(i.priv, body)
	return Encode(p, sig)
}
