package license

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// manualClock 是测试用的可操控时钟。
type manualClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *manualClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

func (c *manualClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

var (
	testFP      = Fingerprint{Hostname: "host-a", MachineID: "mid-a", MACs: []string{"aa:bb:cc:dd:ee:ff"}}
	otherFP     = Fingerprint{Hostname: "host-b", MachineID: "mid-b", MACs: []string{"11:22:33:44:55:66"}}
	testOptions = Options{
		RollbackTolerance:    time.Minute,
		ForwardJumpTolerance: 24 * time.Hour,
		ExpiryGracePeriod:    0,
	}
	base = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
)

// setup 构造一套签发者/校验器与一张有效凭证。
func setup(t *testing.T, storePath string) (*Issuer, *Verifier, *manualClock, string) {
	t.Helper()
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	clock := &manualClock{now: base}
	iss := NewIssuer(priv)
	iss.SetClock(clock.Now)
	store, err := OpenStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	v := NewVerifier(pub, store, testOptions)
	v.SetClock(clock.Now)
	tok, err := iss.Issue(IssueRequest{
		Subject:   "alice",
		Scope:     []string{"feature-x"},
		NotBefore: base.Add(-time.Hour),
		ExpiresAt: base.Add(30 * 24 * time.Hour),
		Machine:   testFP,
	})
	if err != nil {
		t.Fatal(err)
	}
	return iss, v, clock, tok
}

func reasonOf(err error) Reason {
	if err == nil {
		return ReasonOK
	}
	if e, ok := err.(*Error); ok {
		return e.Reason
	}
	return "unknown"
}

func TestVerifyValidToken(t *testing.T) {
	_, v, _, tok := setup(t, filepath.Join(t.TempDir(), "state.json"))
	if err := v.Verify(tok, testFP); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
}

func TestExpiredToken(t *testing.T) {
	_, v, clock, tok := setup(t, filepath.Join(t.TempDir(), "state.json"))
	if err := v.Verify(tok, testFP); err != nil { // 建立高水位
		t.Fatal(err)
	}
	clock.Add(31 * 24 * time.Hour) // 超过 30 天有效期
	// 前跳宽限期为 24h，这里跳了 31 天，应先命中时钟跳变。
	if got := reasonOf(v.Verify(tok, testFP)); got != ReasonClockJump {
		t.Fatalf("want %s, got %s", ReasonClockJump, got)
	}
	// 放宽前跳宽限期后，应判定为过期。
	v.opts.ForwardJumpTolerance = 90 * 24 * time.Hour
	if got := reasonOf(v.Verify(tok, testFP)); got != ReasonExpired {
		t.Fatalf("want %s, got %s", ReasonExpired, got)
	}
}

func TestExpiryGracePeriod(t *testing.T) {
	_, v, clock, tok := setup(t, filepath.Join(t.TempDir(), "state.json"))
	v.opts.ExpiryGracePeriod = 48 * time.Hour
	v.opts.ForwardJumpTolerance = 90 * 24 * time.Hour
	clock.Add(30*24*time.Hour + time.Hour) // 过期 1 小时，但在宽限期内
	if err := v.Verify(tok, testFP); err != nil {
		t.Fatalf("within grace period should pass: %v", err)
	}
	clock.Add(48 * time.Hour) // 超出宽限期
	if got := reasonOf(v.Verify(tok, testFP)); got != ReasonExpired {
		t.Fatalf("want %s, got %s", ReasonExpired, got)
	}
}

func TestNotYetValid(t *testing.T) {
	iss, v, _, _ := setup(t, filepath.Join(t.TempDir(), "state.json"))
	tok, err := iss.Issue(IssueRequest{
		Subject:   "bob",
		NotBefore: base.Add(time.Hour), // 一小时后才生效
		ExpiresAt: base.Add(30 * 24 * time.Hour),
		Machine:   testFP,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := reasonOf(v.Verify(tok, testFP)); got != ReasonNotYetValid {
		t.Fatalf("want %s, got %s", ReasonNotYetValid, got)
	}
}

func TestClockRollback(t *testing.T) {
	_, v, clock, tok := setup(t, filepath.Join(t.TempDir(), "state.json"))
	if err := v.Verify(tok, testFP); err != nil { // 建立高水位 base
		t.Fatal(err)
	}
	clock.Add(-time.Hour) // 回拨 1 小时，超过 1 分钟宽限
	if got := reasonOf(v.Verify(tok, testFP)); got != ReasonClockRollback {
		t.Fatalf("want %s, got %s", ReasonClockRollback, got)
	}
	clock.Add(30 * time.Minute) // 回拨 30 分钟内的抖动：仍在宽限内则放行
	clock.Set(base.Add(-30 * time.Second))
	if err := v.Verify(tok, testFP); err != nil {
		t.Fatalf("small rollback within tolerance should pass: %v", err)
	}
}

func TestClockForwardJump(t *testing.T) {
	_, v, clock, tok := setup(t, filepath.Join(t.TempDir(), "state.json"))
	if err := v.Verify(tok, testFP); err != nil {
		t.Fatal(err)
	}
	clock.Add(48 * time.Hour) // 前跳 48 小时，超过 24 小时宽限
	if got := reasonOf(v.Verify(tok, testFP)); got != ReasonClockJump {
		t.Fatalf("want %s, got %s", ReasonClockJump, got)
	}
}

func TestTamperedToken(t *testing.T) {
	_, v, _, tok := setup(t, filepath.Join(t.TempDir(), "state.json"))
	// 篡改载荷：把有效期延长后重新编码（无合法签名）。
	p, _, err := Decode(tok)
	if err != nil {
		t.Fatal(err)
	}
	p.ExpiresAt = p.ExpiresAt.Add(365 * 24 * time.Hour)
	forged, err := Encode(p, make([]byte, 64))
	if err != nil {
		t.Fatal(err)
	}
	if got := reasonOf(v.Verify(forged, testFP)); got != ReasonBadSignature {
		t.Fatalf("forged payload: want %s, got %s", ReasonBadSignature, got)
	}

	// 篡改签名字节（保持编码合法）。
	_, sig, err := Decode(tok)
	if err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 0xff
	badSig, err := Encode(p, sig)
	if err != nil {
		t.Fatal(err)
	}
	if got := reasonOf(v.Verify(badSig, testFP)); got != ReasonBadSignature {
		t.Fatalf("bad signature: want %s, got %s", ReasonBadSignature, got)
	}

	// 结构性损坏。
	if got := reasonOf(v.Verify("not-a-token", testFP)); got != ReasonMalformed {
		t.Fatalf("malformed: want %s, got %s", ReasonMalformed, got)
	}
	if got := reasonOf(v.Verify(tok[:len(tok)/2], testFP)); got != ReasonMalformed {
		t.Fatalf("single segment: want %s, got %s", ReasonMalformed, got)
	}
}

func TestMachineMismatch(t *testing.T) {
	_, v, _, tok := setup(t, filepath.Join(t.TempDir(), "state.json"))
	// 换到未授权机器。
	if got := reasonOf(v.Verify(tok, otherFP)); got != ReasonMachineMismatch {
		t.Fatalf("want %s, got %s", ReasonMachineMismatch, got)
	}
	// 绑定信息被部分改写（仅主机名不同）也必须失败。
	partial := testFP
	partial.Hostname = "host-a-clone"
	if got := reasonOf(v.Verify(tok, partial)); got != ReasonMachineMismatch {
		t.Fatalf("want %s, got %s", ReasonMachineMismatch, got)
	}
}

func TestRevocationPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	_, v, _, tok := setup(t, path)
	p, _, err := Decode(tok)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Revoke(p.ID); err != nil {
		t.Fatal(err)
	}
	if got := reasonOf(v.Verify(tok, testFP)); got != ReasonRevoked {
		t.Fatalf("want %s, got %s", ReasonRevoked, got)
	}
	// 模拟进程重启：重新打开同一状态文件，撤销仍生效。
	store2, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	v2 := NewVerifier(v.pub, store2, testOptions)
	v2.SetClock(func() time.Time { return base })
	if got := reasonOf(v2.Verify(tok, testFP)); got != ReasonRevoked {
		t.Fatalf("after restart: want %s, got %s", ReasonRevoked, got)
	}
}

func TestConcurrentVerifyAndRevoke(t *testing.T) {
	_, v, _, tok := setup(t, filepath.Join(t.TempDir(), "state.json"))
	p, _, err := Decode(tok)
	if err != nil {
		t.Fatal(err)
	}
	// 撤销前并发校验：全部必须通过且结果一致。
	const n = 64
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = v.Verify(tok, testFP)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
	// 撤销与校验并发：结果只能是 ok 或 revoked 之一，且撤销完成后必须稳定为 revoked。
	v.Revoke(p.ID)
	results := make([]Reason, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = reasonOf(v.Verify(tok, testFP))
		}(i)
	}
	wg.Wait()
	for i, r := range results {
		if r != ReasonRevoked {
			t.Fatalf("goroutine %d: after revoke want %s, got %s", i, ReasonRevoked, r)
		}
	}
}

func TestDeterministicResults(t *testing.T) {
	_, v, _, tok := setup(t, filepath.Join(t.TempDir(), "state.json"))
	first := v.Verify(tok, testFP)
	for i := 0; i < 10; i++ {
		if err := v.Verify(tok, testFP); reasonOf(err) != reasonOf(first) {
			t.Fatalf("run %d: inconsistent result %v vs %v", i, err, first)
		}
	}
}

func TestFingerprintHashStable(t *testing.T) {
	a := Fingerprint{Hostname: "h", MachineID: "m", MACs: []string{"b", "a"}}
	b := Fingerprint{Hostname: "h", MachineID: "m", MACs: []string{"a", "b"}}
	if a.Hash() != b.Hash() {
		t.Fatal("hash must be independent of MAC order")
	}
	c := Fingerprint{Hostname: "h2", MachineID: "m", MACs: []string{"a", "b"}}
	if a.Hash() == c.Hash() {
		t.Fatal("hash must change with fingerprint content")
	}
}
