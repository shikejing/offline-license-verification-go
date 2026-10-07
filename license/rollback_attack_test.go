package license

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// issueAt 用给定签发者签发一张自定义时间窗口的凭证。
func issueAt(t *testing.T, iss *Issuer, issued, nb, exp time.Time) string {
	t.Helper()
	old := iss.now
	iss.SetClock(func() time.Time { return issued })
	defer iss.SetClock(old)
	tok, err := iss.Issue(IssueRequest{
		Subject:   "timed",
		NotBefore: nb,
		ExpiresAt: exp,
		Machine:   testFP,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func mustID(t *testing.T, tok string) string {
	t.Helper()
	p, _, err := Decode(tok)
	if err != nil {
		t.Fatal(err)
	}
	return p.ID
}

// 场景一（核心绕过）：有效期内通过 -> 到期后被拒 -> 把时间回拨回窗口，
// 必须继续被拒，且原因稳定为 expired，可与时钟类失败区分。
func TestExpiredThenRollbackIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	_, v, clock, tok := setup(t, path)
	p, _, err := Decode(tok)
	if err != nil {
		t.Fatal(err)
	}

	// 1. 有效期内校验通过。
	if err := v.Verify(tok, testFP); err != nil {
		t.Fatalf("valid window should pass: %v", err)
	}

	// 2. 时间自然推进到有效期之后（放宽前跳宽限，使读数通过时钟检查），
	//    凭证被拒，原因 expired，并落下墓碑。
	v.opts.ForwardJumpTolerance = 365 * 24 * time.Hour
	clock.Set(base.Add(31 * 24 * time.Hour))
	if got := reasonOf(v.Verify(tok, testFP)); got != ReasonExpired {
		t.Fatalf("after expiry want %s, got %s", ReasonExpired, got)
	}
	if !v.store.IsExpired(p.ID) {
		t.Fatal("expiry tombstone must be recorded after an expired verification")
	}

	// 3. 攻击：把时间回拨回有效窗口。必须继续拒绝，原因稳定为 expired。
	clock.Set(base.Add(time.Hour))
	if got := reasonOf(v.Verify(tok, testFP)); got != ReasonExpired {
		t.Fatalf("rolled-back valid window after expiry: want %s, got %s", ReasonExpired, got)
	}

	// 4. 再来多次失败校验、窗口内时间抖动，结论一致、可复现。
	for i := 0; i < 20; i++ {
		clock.Set(base.Add(time.Duration(i) * time.Minute))
		if r := reasonOf(v.Verify(tok, testFP)); r != ReasonExpired {
			t.Fatalf("iter %d: want %s, got %s", i, ReasonExpired, r)
		}
	}
}

// 场景二：任何读到时间的校验（含凭证自身失败）都必须保留并只推进时间认知，
// 一次拒绝不能让已确认时间点丢失或被改写为更早值。
func TestFailedVerificationsPreserveTimeKnowledge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	iss, v, clock, tok := setup(t, path)
	if err := v.Verify(tok, testFP); err != nil {
		t.Fatal(err)
	}
	confirmed := v.store.LastSeen()
	if confirmed.IsZero() {
		t.Fatal("baseline last_seen must be established")
	}

	// 机器绑定不符：这是凭证自身失败，但已经读到时间，高水位必须前进。
	clock.Set(base.Add(time.Hour))
	if got := reasonOf(v.Verify(tok, otherFP)); got != ReasonMachineMismatch {
		t.Fatalf("want %s, got %s", ReasonMachineMismatch, got)
	}
	if ls := v.store.LastSeen(); !ls.Equal(base.Add(time.Hour)) {
		t.Fatalf("machine-mismatch rejection must still advance time knowledge, got %s", ls)
	}

	// 未生效凭证被拒：读数同样必须保留。
	earlyTok := issueAt(t, iss, base.Add(2*time.Hour), base.Add(3*time.Hour), base.Add(10*24*time.Hour))
	clock.Set(base.Add(2 * time.Hour))
	if got := reasonOf(v.Verify(earlyTok, testFP)); got != ReasonNotYetValid {
		t.Fatalf("want %s, got %s", ReasonNotYetValid, got)
	}
	if ls := v.store.LastSeen(); !ls.Equal(base.Add(2 * time.Hour)) {
		t.Fatalf("not-yet-valid rejection must preserve advanced time, got %s", ls)
	}

	// 结构性损坏在读时间之前就失败：未读到时间，高水位不变。
	clock.Set(base.Add(3 * time.Hour))
	if got := reasonOf(v.Verify("garbage", testFP)); got != ReasonMalformed {
		t.Fatalf("want %s, got %s", ReasonMalformed, got)
	}
	if ls := v.store.LastSeen(); !ls.Equal(base.Add(2 * time.Hour)) {
		t.Fatalf("pre-clock malformed verification must not move time, got %s", ls)
	}

	// 已确认的时间点仍在：把时钟回拨超过宽限，必须识别为回拨而非放行。
	clock.Set(confirmed.Add(-2 * time.Hour))
	if got := reasonOf(v.Verify(tok, testFP)); got != ReasonClockRollback {
		t.Fatalf("want %s, got %s", ReasonClockRollback, got)
	}
}

// 场景三：异常向前跳变被挡下后，本机时间认知不被带偏；时间恢复正常后，
// 未过期凭证照常通过，且跳变读数不会误写过期墓碑。
func TestForwardJumpIsolation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	_, v, clock, tok := setup(t, path) // 前跳宽限 24h
	if err := v.Verify(tok, testFP); err != nil {
		t.Fatal(err)
	}
	before := v.store.LastSeen()

	clock.Set(base.Add(48 * time.Hour))
	if got := reasonOf(v.Verify(tok, testFP)); got != ReasonClockJump {
		t.Fatalf("want %s, got %s", ReasonClockJump, got)
	}
	if ls := v.store.LastSeen(); !ls.Equal(before) {
		t.Fatalf("forward jump must not move high-water mark: before=%s after=%s", before, ls)
	}
	if v.store.IsExpired(mustID(t, tok)) {
		t.Fatal("a jump-rejected reading must not mark the license expired")
	}

	// 恢复到窗口内：未过期凭证正常通过，时间认知随可信读数继续前进。
	clock.Set(base.Add(time.Hour))
	if err := v.Verify(tok, testFP); err != nil {
		t.Fatalf("recovered clock must allow valid token: %v", err)
	}
	if ls := v.store.LastSeen(); !ls.Equal(base.Add(time.Hour)) {
		t.Fatalf("time knowledge should advance with recovered reading, got %s", ls)
	}

	// 再来一轮跳变/恢复，行为依旧。
	clock.Set(base.Add(48 * time.Hour))
	if got := reasonOf(v.Verify(tok, testFP)); got != ReasonClockJump {
		t.Fatalf("second jump: want %s, got %s", ReasonClockJump, got)
	}
	clock.Set(base.Add(2 * time.Hour))
	if err := v.Verify(tok, testFP); err != nil {
		t.Fatalf("second recovery should pass: %v", err)
	}
}

// 场景四：过期墓碑与高水位在进程重启后仍生效；无论重启几次、时间是否回拨，
// 已确认过期的凭证都稳定返回 expired。
func TestConstraintsSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	iss, v, clock, tok := setup(t, path)
	pub := ed25519.PublicKey(iss.priv[32:])

	v.opts.ForwardJumpTolerance = 365 * 24 * time.Hour
	clock.Set(base.Add(31 * 24 * time.Hour))
	if got := reasonOf(v.Verify(tok, testFP)); got != ReasonExpired {
		t.Fatalf("want %s, got %s", ReasonExpired, got)
	}

	// 重启 #1：时间被调回窗口内，仍 expired；高水位也保留。
	store1, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	v1 := NewVerifier(pub, store1, testOptions)
	v1.SetClock((&manualClock{now: base.Add(time.Hour)}).Now)
	if got := reasonOf(v1.Verify(tok, testFP)); got != ReasonExpired {
		t.Fatalf("restart 1 after rollback: want %s, got %s", ReasonExpired, got)
	}
	if ls := store1.LastSeen(); !ls.Equal(base.Add(31 * 24 * time.Hour)) {
		t.Fatalf("high-water mark must survive restart, got %s", ls)
	}
	store1.Close()

	// 重启 #2：再次确认，结论一致。
	store2, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	v2 := NewVerifier(pub, store2, testOptions)
	v2.SetClock((&manualClock{now: base.Add(2 * time.Hour)}).Now)
	if got := reasonOf(v2.Verify(tok, testFP)); got != ReasonExpired {
		t.Fatalf("restart 2: want %s, got %s", ReasonExpired, got)
	}
	store2.Close()
}

// 场景五：成功与失败路径在多个校验器上高度并发交错，结果确定、状态不损坏。
func TestInterleavedSuccessAndFailureConcurrency(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	iss, v, _, tok := setup(t, path)
	// 一张在基线时刻就已过期的凭证：在单调时间线上始终返回 expired。
	expiredTok := issueAt(t, iss, base.Add(-2*time.Hour), base.Add(-3*time.Hour), base.Add(-time.Hour))

	// 全局严格单调时间源，每次读数原子 +1s。成功/失败/墓碑写入交错，
	// 但各校验器读到的时间不会互相回退，因而不应触发时钟类拒绝。
	var ticks int64
	monoNow := func() time.Time {
		n := atomic.AddInt64(&ticks, 1)
		return base.Add(time.Duration(n) * time.Second)
	}

	const workers = 16
	const rounds = 25
	var wg sync.WaitGroup
	errs := make(chan error, workers*rounds*2)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			vv := NewVerifier(v.pub, v.store, Options{
				RollbackTolerance:    time.Minute,
				ForwardJumpTolerance: 365 * 24 * time.Hour,
			})
			vv.SetClock(monoNow)
			for r := 0; r < rounds; r++ {
				if err := vv.Verify(tok, testFP); err != nil {
					errs <- err
					return
				}
				if got := reasonOf(vv.Verify(expiredTok, testFP)); got != ReasonExpired {
					errs <- &Error{Reason: got, Detail: "want expired from interleaved worker"}
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("interleaved verify mismatch: %v", err)
	}

	// 交错后不变量：时间认知只前进；过期墓碑保留，回拨仍 expired；
	// 时间继续沿时间线前进，好凭证仍通过（异常不带偏认知）。
	last := v.store.LastSeen()
	if !last.After(base) {
		t.Fatalf("time knowledge must have advanced, got %s", last)
	}
	if !v.store.IsExpired(mustID(t, expiredTok)) {
		t.Fatal("expired tombstone must persist after interleaving")
	}
	v.SetClock((&manualClock{now: base.Add(time.Second)}).Now)
	if got := reasonOf(v.Verify(expiredTok, testFP)); got != ReasonExpired {
		t.Fatalf("expired token at rolled-back time: want %s, got %s", ReasonExpired, got)
	}
	v.SetClock((&manualClock{now: last.Add(time.Second)}).Now)
	if err := v.Verify(tok, testFP); err != nil {
		t.Fatalf("valid token further along timeline should pass: %v", err)
	}
}

// 两个独立 store（模拟两个进程）并发写同一状态文件，跨进程锁 + 重读合并
// 必须保证任一方的高水位推进都不丢失。
func TestTwoStoresConcurrentWritesDoNotLoseState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	iss, v, _, tok := setup(t, path)
	pub := ed25519.PublicKey(iss.priv[32:])
	if err := v.Verify(tok, testFP); err != nil {
		t.Fatal(err)
	}

	storeB, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer storeB.Close()

	var ticks int64 = 1
	monoNow := func() time.Time {
		n := atomic.AddInt64(&ticks, 1)
		return base.Add(time.Duration(n) * time.Second)
	}
	va := NewVerifier(pub, v.store, Options{
		RollbackTolerance:    time.Minute,
		ForwardJumpTolerance: 365 * 24 * time.Hour,
	})
	va.SetClock(monoNow)
	vb := NewVerifier(pub, storeB, Options{
		RollbackTolerance:    time.Minute,
		ForwardJumpTolerance: 365 * 24 * time.Hour,
	})
	vb.SetClock(monoNow)

	const n = 40
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := va.Verify(tok, testFP); err != nil {
				t.Errorf("store A verify: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			if err := vb.Verify(tok, testFP); err != nil {
				t.Errorf("store B verify: %v", err)
			}
		}()
	}
	wg.Wait()

	final, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer final.Close()
	want := base.Add(time.Duration(atomic.LoadInt64(&ticks)) * time.Second)
	if got := final.LastSeen(); !got.Equal(want) {
		t.Fatalf("cross-store high-water merge lost updates: want %s got %s", want, got)
	}
}

// 高强度并发写下，正式状态文件始终是完整可解析 JSON，不残留半截临时文件。
func TestStateFileIsNeverTruncatedOrCorrupted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	_, v, _, tok := setup(t, path)
	if err := v.Verify(tok, testFP); err != nil {
		t.Fatal(err)
	}

	const n = 60
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			_ = v.Revoke("rev-" + strconv.Itoa(i))
		}
	}()
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			vv := NewVerifier(v.pub, v.store, Options{
				RollbackTolerance:    0,
				ForwardJumpTolerance: 365 * 24 * time.Hour,
			})
			vv.SetClock((&manualClock{now: base.Add(time.Duration(i) * time.Second)}).Now)
			_ = vv.Verify(tok, testFP)
		}(i)
	}
	wg.Wait()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var st state
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatalf("state file must be complete valid JSON after concurrent writes: %v\n%s", err, b)
	}
	if st.LastSeen.IsZero() {
		t.Fatal("last_seen must be persisted")
	}
	if len(st.Revoked) == 0 {
		t.Fatal("revocations must be persisted")
	}
	matches, _ := filepath.Glob(filepath.Join(dir, ".state.json.tmp-*"))
	if len(matches) != 0 {
		t.Fatalf("renamed temp files should not linger: %v", matches)
	}
}

// 旧版本状态文件（无 expired 字段）可直接读取，撤销语义不变，缺失字段按空处理。
func TestLegacyStateFileWithoutExpiredFieldLoads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	legacy := map[string]interface{}{
		"revoked":   []string{"old-license-1"},
		"last_seen": base.Add(10 * 24 * time.Hour).Format(time.RFC3339Nano),
	}
	b, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := OpenStore(path)
	if err != nil {
		t.Fatalf("legacy state must load without migration: %v", err)
	}
	if !store.IsRevoked("old-license-1") {
		t.Fatal("legacy revocation semantics must be preserved")
	}
	if store.IsExpired("anything") {
		t.Fatal("missing expired field must be treated as empty on first run")
	}
	if got := store.LastSeen(); !got.Equal(base.Add(10 * 24 * time.Hour)) {
		t.Fatalf("legacy last_seen must be preserved, got %s", got)
	}

	if err := store.MarkExpired("new-license"); err != nil {
		t.Fatal(err)
	}
	store.Close()

	store2, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store2.Close()
	if !store2.IsRevoked("old-license-1") || !store2.IsExpired("new-license") {
		t.Fatal("state must round-trip both legacy revoked and new expired")
	}
}

// 状态文件中无法识别的新字段应被忽略，不影响已知字段加载。
func TestFutureExtraFieldsAreIgnored(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	raw := `{"revoked":["x"],"last_seen":"2026-01-01T00:00:00Z","expired":["y"],"future_field":123,"nested":{"a":1}}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(path)
	if err != nil {
		t.Fatalf("unknown future fields must be tolerated: %v", err)
	}
	defer store.Close()
	if !store.IsRevoked("x") || !store.IsExpired("y") {
		t.Fatal("known fields must still load alongside unknown ones")
	}
}
