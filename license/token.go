package license

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Payload 是凭证的载荷，签名覆盖其规范化编码。
type Payload struct {
	ID          string    `json:"id"`
	Subject     string    `json:"subject"`
	Scope       []string  `json:"scope"`
	IssuedAt    time.Time `json:"issued_at"`
	NotBefore   time.Time `json:"not_before"`
	ExpiresAt   time.Time `json:"expires_at"`
	MachineHash string    `json:"machine_hash"`
	Nonce       string    `json:"nonce"`
}

// canonical 返回载荷的规范化字节表示。
// JSON 序列化后字段顺序固定（按结构体声明顺序），
// 时间统一为 UTC，保证签名与载荷的绑定完整且可复现。
func (p *Payload) canonical() ([]byte, error) {
	q := *p
	q.IssuedAt = q.IssuedAt.UTC()
	q.NotBefore = q.NotBefore.UTC()
	q.ExpiresAt = q.ExpiresAt.UTC()
	if q.Scope == nil {
		q.Scope = []string{}
	}
	b, err := json.Marshal(&q)
	if err != nil {
		return nil, fmt.Errorf("canonicalize payload: %w", err)
	}
	return b, nil
}

// Encode 将载荷与签名编码为凭证字符串：base64url(payload).base64url(sig)。
func Encode(p *Payload, sig []byte) (string, error) {
	body, err := p.canonical()
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(body) + "." + enc.EncodeToString(sig), nil
}

// Decode 解析凭证字符串为载荷与签名（不校验签名）。
// 解析失败统一归为 ReasonMalformed。
func Decode(tok string) (*Payload, []byte, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, nil, &Error{Reason: ReasonMalformed, Detail: "token must have exactly two segments"}
	}
	enc := base64.RawURLEncoding
	body, err := enc.DecodeString(parts[0])
	if err != nil {
		return nil, nil, &Error{Reason: ReasonMalformed, Detail: "payload segment is not valid base64url"}
	}
	sig, err := enc.DecodeString(parts[1])
	if err != nil {
		return nil, nil, &Error{Reason: ReasonMalformed, Detail: "signature segment is not valid base64url"}
	}
	var p Payload
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, nil, &Error{Reason: ReasonMalformed, Detail: "payload is not valid JSON: " + err.Error()}
	}
	if p.ID == "" {
		return nil, nil, &Error{Reason: ReasonMalformed, Detail: "payload missing id"}
	}
	// 重新规范化并与原字节比较：拒绝非规范编码，确保“签名所见即校验所用”。
	re, err := p.canonical()
	if err != nil {
		return nil, nil, &Error{Reason: ReasonMalformed, Detail: "payload cannot be canonicalized"}
	}
	if string(re) != string(body) {
		return nil, nil, &Error{Reason: ReasonMalformed, Detail: "payload is not in canonical form"}
	}
	return &p, sig, nil
}
