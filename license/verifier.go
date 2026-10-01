package license

import (
	"crypto/ed25519"
	"crypto/subtle"
	"fmt"
	"sync"
	"time"
)

// Options 控制校验的宽限期策略。
type Options struct {
	// RollbackTolerance 允许的最大时钟回拨；超过则判定时钟回拨异常。
	RollbackTolerance time.Duration
	// ForwardJumpTolerance 允许的最大向前跳变；超过则判定时钟跳变异常。
	ForwardJumpTolerance time.Duration
	// ExpiryGracePeriod 到期后的宽限期，宽限期内仍放行。
	ExpiryGracePeriod time.Duration
}

// Verifier 在本地进程内校验凭证，可并发使用。
type Verifier struct {
	pub   ed25519.PublicKey
	opts  Options
	store *StateStore
	now   func() time.Time

	// mu 串行化“读高水位→判定→写高水位”的临界区，
	// 保证并发校验结果确定且可追溯。
	mu sync.Mutex
}

// NewVerifier 创建校验器。store 为 nil 时使用纯内存状态（不持久化）。
func NewVerifier(pub ed25519.PublicKey, store *StateStore, opts Options) *Verifier {
	if store == nil {
		store, _ = OpenStore("")
	}
	return &Verifier{pub: pub, opts: opts, store: store, now: time.Now}
}

// SetClock 注入时间来源（测试用）。
func (v *Verifier) SetClock(now func() time.Time) { v.now = now }

// Verify 校验凭证与当前机器指纹。
// 失败时返回 *Error，其 Reason 可区分：
// malformed_token / bad_signature / revoked / machine_mismatch /
// clock_rollback / clock_jump / not_yet_valid / expired。
// 检查顺序固定，因此相同输入的结果确定且可复现。
func (v *Verifier) Verify(tok string, fp Fingerprint) error {
	p, sig, err := Decode(tok)
	if err != nil {
		return err
	}

	// 1. 签名：覆盖载荷的完整规范化编码，任何字段被改写都会失败。
	body, err := p.canonical()
	if err != nil {
		return &Error{Reason: ReasonMalformed, Detail: err.Error()}
	}
	if len(v.pub) != ed25519.PublicKeySize || !ed25519.Verify(v.pub, body, sig) {
		return &Error{Reason: ReasonBadSignature, Detail: "signature does not match payload"}
	}

	// 2. 撤销：本地持久化状态，无需网络。
	if v.store.IsRevoked(p.ID) {
		return &Error{Reason: ReasonRevoked, Detail: "license " + p.ID + " has been revoked"}
	}

	// 3. 机器绑定：常量时间比较，绑定信息被改写或换机都会失败。
	if subtle.ConstantTimeCompare([]byte(p.MachineHash), []byte(fp.Hash())) != 1 {
		return &Error{Reason: ReasonMachineMismatch, Detail: "token is bound to a different machine"}
	}

	// 4. 时钟异常与 5. 有效期：与观测高水位的更新放在同一临界区，
	// 保证并发下判定与状态推进是原子的。
	v.mu.Lock()
	defer v.mu.Unlock()

	now := v.now().UTC()
	if err := v.checkClock(now); err != nil {
		return err
	}
	if now.Before(p.NotBefore) {
		return &Error{Reason: ReasonNotYetValid, Detail: fmt.Sprintf("valid from %s", p.NotBefore.Format(time.RFC3339))}
	}
	if now.After(p.ExpiresAt.Add(v.opts.ExpiryGracePeriod)) {
		return &Error{Reason: ReasonExpired, Detail: fmt.Sprintf("expired at %s", p.ExpiresAt.Format(time.RFC3339))}
	}

	// 校验通过后才推进高水位，失败不污染状态。
	return v.store.Observe(now)
}

// checkClock 依据高水位与宽限期策略识别异常时间，而不是直接信任本地时间。
func (v *Verifier) checkClock(now time.Time) error {
	last := v.store.LastSeen()
	if last.IsZero() {
		return nil // 首次运行，无基线可比对
	}
	if now.Before(last.Add(-v.opts.RollbackTolerance)) {
		return &Error{Reason: ReasonClockRollback, Detail: fmt.Sprintf("local clock %s is behind last observed %s beyond tolerance", now.Format(time.RFC3339), last.Format(time.RFC3339))}
	}
	if v.opts.ForwardJumpTolerance > 0 && now.After(last.Add(v.opts.ForwardJumpTolerance)) {
		return &Error{Reason: ReasonClockJump, Detail: fmt.Sprintf("local clock %s jumped forward from last observed %s beyond tolerance", now.Format(time.RFC3339), last.Format(time.RFC3339))}
	}
	return nil
}

// Revoke 撤销指定凭证 ID，立即持久化，重启后仍生效。
func (v *Verifier) Revoke(id string) error { return v.store.Revoke(id) }
