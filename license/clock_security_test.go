package license

import (
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"testing"
	"time"
)

// reopenStore 模拟进程重启：用一个全新的 StateStore 句柄重新打开同一状态文件。
func reopenStore(t *testing.T, path string) *StateStore {
	t.Helper()
	s, err := OpenStore(path)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// issueToken 用给定签发者签发一张指定有效期、绑定 testFP 的凭证。
func issueToken(t *testing.T, iss *Issuer, nb, exp time.Time) string {
	t.Helper()
	tok, err := iss.Issue(IssueRequest{
		Subject:   "alice",
		NotBefore: nb,
		ExpiresAt: exp,
		Machine:   testFP,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestExpiredThenRollbackStaysRejected 复现上报的绕过手法：
// 有效期内通过 -> 时间拨到过期后被拒 -> 时间调回有效期内，凭证必须仍被拒绝，
// 且拒绝原因稳定为 expired（而不是 clock_rollback），多次校验结果一致。
func TestExpiredThenRollbackStaysRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	_, v, clock, tok := setup(t, path)
	// 前跳宽限放大，避免“拨到过期之后”这一步先被 clock_jump 挡住而测不到过期语义。
	v.opts.ForwardJumpTolerance = 365 * 24 * time.Hour

	if err := v.Verify(tok, testFP); err != nil {
		t.Fatalf("valid token should pass: %v", err)
	}

	// 时间越过到期点：过期被确认并持久化。
	clock.Set(base.Add(31 * 24 * time.Hour))
	if got := reasonOf(v.Verify(tok, testFP)); got != ReasonExpired {
		t.Fatalf("past expiry: want %s, got %s", ReasonExpired, got)
	}

	// 同一张已过期凭证，时间调回有效窗口内（甚至回到窗口深处），必须持续拒绝。
	for _, back := range []time.Duration{29 * 24 * time.Hour, 10 * 24 * time.Hour, time.Hour} {
		clock.Set(base.Add(back))
		for i := 0; i < 3; i++ { // 同输入多次，结果必须可复现
			if got := reasonOf(v.Verify(tok, testFP)); got != ReasonExpired {
				t.Fatalf("rollback into window (%s, run %d): want %s, got %s", back, i, ReasonExpired, got)
			}
		}
	}

	// 进程重启后约束仍生效。
	store2 := reopenStore(t, path)
	v2 := NewVerifier(v.pub, store2, v.opts)
	v2.SetClock(clock.Now)
	clock.Set(base.Add(10 * 24 * time.Hour))
	if got := reasonOf(v2.Verify(tok, testFP)); got != ReasonExpired {
		t.Fatalf("after restart in window: want %s, got %s", ReasonExpired, got)
	}
}

// TestExpiryReasonSeparatedFromClockRollback 同一高水位下：
// 过期凭证给出 expired，未过期凭证给出 clock_rollback，两类原因稳定可区分。
func TestExpiryReasonSeparatedFromClockRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	iss, v, clock, tok := setup(t, path)
	v.opts.ForwardJumpTolerance = 365 * 24 * time.Hour
	longTok := issueToken(t, iss, base.Add(-time.Hour), base.Add(365*24*time.Hour))

	clock.Set(base.Add(31 * 24 * time.Hour))
	if got := reasonOf(v.Verify(tok, testFP)); got != ReasonExpired {
		t.Fatalf("want %s, got %s", ReasonExpired, got)
	}

	// 时间调回窗口内：短证已被确认过期 -> expired；
	// 长证在该时间点本身没过期，纯粹是时钟回拨 -> clock_rollback。
	clock.Set(base.Add(10 * 24 * time.Hour))
	if got := reasonOf(v.Verify(tok, testFP)); got != ReasonExpired {
		t.Fatalf("expired token: want %s, got %s", ReasonExpired, got)
	}
	if got := reasonOf(v.Verify(longTok, testFP)); got != ReasonClockRollback {
		t.Fatalf("unexpired token under rollback: want %s, got %s", ReasonClockRollback, got)
	}
}

// TestFailedVerificationsAdvanceClockKnowledge 需求 1+2：
// 被拒绝的校验（未生效、过期）也必须推进时间认知，且任何失败都不能把
// 高水位改写小。连续失败后再回拨，依然会被 clock_rollback / expired 挡住。
func TestFailedVerificationsAdvanceClockKnowledge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	iss, v, clock, _ := setup(t, path)
	v.opts.ForwardJumpTolerance = 365 * 24 * time.Hour

	// 未生效凭证在 base+5d 被拒，但该时间受信任，认知必须推进到 base+5d。
	early := issueToken(t, iss, base.Add(10*24*time.Hour), base.Add(40*24*time.Hour))
	clock.Set(base.Add(5 * 24 * time.Hour))
	if got := reasonOf(v.Verify(early, testFP)); got != ReasonNotYetValid {
		t.Fatalf("want %s, got %s", ReasonNotYetValid, got)
	}
	if got := v.store.LastSeen(); !got.Equal(base.Add(5 * 24 * time.Hour)) {
		t.Fatalf("not_yet_valid must still advance high-water mark, got %s", got)
	}

	// 过期凭证在 base+31d 被拒，认知继续前进。
	exp := issueToken(t, iss, base.Add(-time.Hour), base.Add(20*24*time.Hour))
	clock.Set(base.Add(31 * 24 * time.Hour))
	if got := reasonOf(v.Verify(exp, testFP)); got != ReasonExpired {
		t.Fatalf("want %s, got %s", ReasonExpired, got)
	}
	if got := v.store.LastSeen(); !got.Equal(base.Add(31 * 24 * time.Hour)) {
		t.Fatalf("expired must advance high-water mark, got %s", got)
	}

	// 异常回拨（base+2d，落后高水位 29 天）不得把认知拉回去。
	clock.Set(base.Add(2 * 24 * time.Hour))
	if got := reasonOf(v.Verify(exp, testFP)); got != ReasonExpired {
		t.Fatalf("rollback after expiry: want %s, got %s", ReasonExpired, got)
	}
	if got := v.store.LastSeen(); !got.Equal(base.Add(31 * 24 * time.Hour)) {
		t.Fatalf("failed/abnormal verification must not move high-water backwards, got %s", got)
	}
}

// TestForwardJumpIsolation 需求 3：异常前跳被挡住后，时间认知不被带偏；
// 把时间恢复到正常值（宽限以内）后，未过期凭证正常通过，且认知停留在跳变前。
func TestForwardJumpIsolation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	_, v, clock, tok := setup(t, path)

	if err := v.Verify(tok, testFP); err != nil {
		t.Fatal(err)
	}
	mark := v.store.LastSeen()

	// 前跳 48h（超过 24h 宽限）：拒绝且高水位保持 base。
	clock.Set(base.Add(48 * time.Hour))
	if got := reasonOf(v.Verify(tok, testFP)); got != ReasonClockJump {
		t.Fatalf("want %s, got %s", ReasonClockJump, got)
	}
	if got := v.store.LastSeen(); !got.Equal(mark) {
		t.Fatalf("forward jump must not advance clock knowledge: got %s want %s", got, mark)
	}

	// 再试几次异常时间，认知依旧不动。
	clock.Set(base.Add(72 * time.Hour))
	if got := reasonOf(v.Verify(tok, testFP)); got != ReasonClockJump {
		t.Fatalf("want %s, got %s", ReasonClockJump, got)
	}

	// 恢复到正常值（base+1h，在宽限内）：未过期凭证通过。
	clock.Set(base.Add(time.Hour))
	if err := v.Verify(tok, testFP); err != nil {
		t.Fatalf("valid token must pass after clock restored: %v", err)
	}
	if got, want := v.store.LastSeen(), base.Add(time.Hour); !got.Equal(want) {
		t.Fatalf("knowledge should resume from real time: got %s want %s", got, want)
	}
}

// TestClockKnowledgePersistsAcrossRestart 需求 2+5：高水位随状态文件持久化，
// 进程重启后回拨仍被识别；重启后用“过期那一刻”的时间确认过期，再回拨仍拒绝。
func TestClockKnowledgePersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	_, v, clock, tok := setup(t, path)
	v.opts.ForwardJumpTolerance = 365 * 24 * time.Hour

	if err := v.Verify(tok, testFP); err != nil {
		t.Fatal(err)
	}
	clock.Set(base.Add(31 * 24 * time.Hour))
	if got := reasonOf(v.Verify(tok, testFP)); got != ReasonExpired {
		t.Fatalf("want %s, got %s", ReasonExpired, got)
	}

	// 重启：新句柄、新校验器、新进程视角，时间调回窗口内。
	store2 := reopenStore(t, path)
	if got := store2.LastSeen(); !got.Equal(base.Add(31 * 24 * time.Hour)) {
		t.Fatalf("high-water mark lost across restart: %s", got)
	}
	v2 := NewVerifier(v.pub, store2, v.opts)
	clock.Set(base.Add(5 * 24 * time.Hour))
	v2.SetClock(clock.Now)
	if got := reasonOf(v2.Verify(tok, testFP)); got != ReasonExpired {
		t.Fatalf("after restart, rollback into window: want %s, got %s", ReasonExpired, got)
	}

	// 再重启一次，回拨认知同样保留（落后高水位超出回拨宽限）。
	store3 := reopenStore(t, path)
	v3 := NewVerifier(v.pub, store3, testOptions) // 恢复默认 24h 前跳宽限也无关
	clock.Set(base.Add(time.Hour))
	v3.SetClock(clock.Now)
	if got := reasonOf(v3.Verify(tok, testFP)); got != ReasonExpired {
		t.Fatalf("second restart: want %s, got %s", ReasonExpired, got)
	}
}

// TestConcurrentSuccessAndFailureInterleaving 需求 4+5：成功与失败路径
// （过期、回拨、正常、撤销）并发交错时，同一时钟输入下所有结果一致可复现，
// 高水位只进不退，状态文件始终可重新打开。
func TestConcurrentSuccessAndFailureInterleaving(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	iss, v, clock, tok := setup(t, path)
	v.opts.ForwardJumpTolerance = 365 * 24 * time.Hour
	expTok := issueToken(t, iss, base.Add(-time.Hour), base.Add(20*24*time.Hour))

	phases := []struct {
		now  time.Time
		want Reason // 对 tok 的期望
	}{
		{now: base, want: ReasonOK},
		{now: base.Add(31 * 24 * time.Hour), want: ReasonExpired}, // tok 在此刻过期
		{now: base.Add(10 * 24 * time.Hour), want: ReasonExpired}, // 回拨复活必须挡住
	}

	const goroutines = 32
	for pi, ph := range phases {
		clock.Set(ph.now)
		var wg sync.WaitGroup
		results := make([]Reason, goroutines*3)
		for i := 0; i < goroutines; i++ {
			wg.Add(3)
			go func(i int) {
				defer wg.Done()
				results[i*3] = reasonOf(v.Verify(tok, testFP))
			}(i)
			go func(i int) {
				defer wg.Done()
				// 过期凭证在所有阶段都只可能是 expired（phase0 时时钟为 base，
				// 该凭证 20d 到期，base 下未过期 -> ok；之后持久过期）。
				results[i*3+1] = reasonOf(v.Verify(expTok, testFP))
			}(i)
			go func(i int) {
				defer wg.Done()
				_ = v.store.LastSeen() // 纯读路径并发交错
				results[i*3+2] = ReasonOK
			}(i)
		}
		wg.Wait()

		for i := 0; i < goroutines; i++ {
			if r := results[i*3]; r != ph.want {
				t.Fatalf("phase %d goroutine %d: tok want %s got %s", pi, i, ph.want, r)
			}
		}
		// expTok：阶段 0 时钟为 base，尚未过期 -> 全部 ok；阶段 1/2 -> expired。
		wantExp := ReasonOK
		if pi >= 1 {
			wantExp = ReasonExpired
		}
		for i := 0; i < goroutines; i++ {
			if r := results[i*3+1]; r != wantExp {
				t.Fatalf("phase %d goroutine %d: expTok want %s got %s", pi, i, wantExp, r)
			}
		}

		// 状态文件在任意交错点都必须可重新打开、不被并发写坏。
		reopenStore(t, path)
	}

	// 撤销与持续失败校验并发交错：撤销提交后对 tok 稳定返回 revoked。
	rp, _, err := Decode(tok)
	if err != nil {
		t.Fatal(err)
	}
	var wg2 sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg2.Add(2)
		go func() { defer wg2.Done(); _ = v.Verify(tok, testFP) }()
		go func() { defer wg2.Done(); _ = v.Verify(expTok, testFP) }()
	}
	if err := v.Revoke(rp.ID); err != nil {
		t.Fatal(err)
	}
	wg2.Wait()
	for i := 0; i < 16; i++ {
		if got := reasonOf(v.Verify(tok, testFP)); got != ReasonRevoked {
			t.Fatalf("after revoke: want %s got %s", ReasonRevoked, got)
		}
	}

	// 高水位最终停留在出现过的最大受信任时间，绝不回退。
	if got := v.store.LastSeen(); got.Before(base.Add(31 * 24 * time.Hour)) {
		t.Fatalf("high-water mark regressed after concurrency: %s", got)
	}
}

// TestConcurrentRevokeAcrossProcesses 两个独立句柄（模拟两个进程）并发
// 撤销不同凭证：彼此的提交都不得丢失，状态文件保持完整可读。
func TestConcurrentRevokeAcrossProcesses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store := reopenStore(t, path)
	other := reopenStore(t, path) // 同一文件的第二个“进程”

	const n = 40
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(2)
		go func(i int) { defer wg.Done(); _ = store.Revoke("a-" + strconv.Itoa(i)) }(i)
		go func(i int) { defer wg.Done(); _ = other.Revoke("b-" + strconv.Itoa(i)) }(i)
	}
	wg.Wait()

	fresh := reopenStore(t, path)
	for i := 0; i < n; i++ {
		if !fresh.IsRevoked("a-" + strconv.Itoa(i)) {
			t.Fatalf("revocation a-%d lost", i)
		}
		if !fresh.IsRevoked("b-" + strconv.Itoa(i)) {
			t.Fatalf("revocation b-%d lost", i)
		}
	}
}

// TestObserveConcurrentAcrossProcesses 多句柄并发观测不同时间后，
// 高水位必须等于最大观测值，没有更新被覆盖丢失。
func TestObserveConcurrentAcrossProcesses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s1 := reopenStore(t, path)
	s2 := reopenStore(t, path)

	var wg sync.WaitGroup
	for i := 1; i <= 30; i++ {
		wg.Add(2)
		d1 := time.Duration(i) * time.Hour
		d2 := time.Duration(60-i) * time.Hour
		go func(d time.Duration) { defer wg.Done(); _ = s1.Observe(base.Add(d)) }(d1)
		go func(d time.Duration) { defer wg.Done(); _ = s2.Observe(base.Add(d)) }(d2)
	}
	wg.Wait()

	want := base.Add(59 * time.Hour) // max(1..30, 30..59)
	if got := reopenStore(t, path).LastSeen(); !got.Equal(want) {
		t.Fatalf("high-water want %s got %s (lost update?)", want, got)
	}
}

// TestLegacyStateFileLoads 需求 6：旧版本写入的状态文件（只有已知字段、
// 或混入未知新字段、或字段缺失）都能继续读取，按首次运行的空值补齐，
// 撤销语义保持不变，无需人工迁移。
func TestLegacyStateFileLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")

	// 1) 只有撤销列表、没有 last_seen 的旧文件。
	mustWriteFile(t, path, []byte(`{"revoked":["lic-legacy"]}`))
	s := reopenStore(t, path)
	if !s.IsRevoked("lic-legacy") {
		t.Fatal("legacy revoked ids must survive load")
	}
	if !s.LastSeen().IsZero() {
		t.Fatalf("missing last_seen must load as zero, got %s", s.LastSeen())
	}

	// 2) 混入未来版本的未知字段时也必须加载成功。
	mustWriteFile(t, path, []byte(`{"revoked":["lic-legacy2"],"last_seen":"2026-01-01T00:00:00Z","future_field":123,"extra":{"a":1}}`))
	s = reopenStore(t, path)
	if !s.IsRevoked("lic-legacy2") {
		t.Fatal("revoked ids must survive unknown fields")
	}
	if got := s.LastSeen(); !got.Equal(base) {
		t.Fatalf("last_seen want %s got %s", base, got)
	}

	// 3) 加载后重新写盘，旧撤销仍然保留（读改写不丢数据）。
	if err := s.Observe(base.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	s = reopenStore(t, path)
	if !s.IsRevoked("lic-legacy2") {
		t.Fatal("revocation lost after observe rewrite")
	}
}

// TestStateFileNeverLeftHalfWritten 需求 5：目录中残留的临时文件不影响
// 状态加载；每次落盘后状态文件本身必须是可解析的完整 JSON。
func TestStateFileNeverLeftHalfWritten(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := reopenStore(t, path)

	// 模拟上一次进程崩溃后残留的半截临时文件。
	mustWriteFile(t, filepath.Join(dir, ".state-deadbeef.tmp"), []byte(`{"revoked":[`))

	for i := 0; i < 25; i++ {
		if err := s.Revoke("lic-" + strconv.Itoa(i)); err != nil {
			t.Fatal(err)
		}
		if err := s.Observe(base.Add(time.Duration(i) * time.Hour)); err != nil {
			t.Fatal(err)
		}
		// 正式状态文件随时可被全新句柄完整读取。
		fresh := reopenStore(t, path)
		if !fresh.IsRevoked("lic-" + strconv.Itoa(i)) {
			t.Fatalf("iteration %d: state not durably readable", i)
		}
	}

	// 加载带残留临时文件的目录仍然成功，且撤销全部在。
	final := reopenStore(t, path)
	for i := 0; i < 25; i++ {
		if !final.IsRevoked("lic-" + strconv.Itoa(i)) {
			t.Fatalf("lic-%d missing", i)
		}
	}
}

// TestDeterministicSameInputSameResult 需求 4：同一张凭证、同一个时间输入，
// 在校验流程各失败阶段上多次运行结果一致可复现。
func TestDeterministicSameInputSameResult(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	_, v, clock, tok := setup(t, path)
	v.opts.ForwardJumpTolerance = 365 * 24 * time.Hour

	// 先在 base+31d 确认过期。
	clock.Set(base.Add(31 * 24 * time.Hour))
	want := reasonOf(v.Verify(tok, testFP))
	if want != ReasonExpired {
		t.Fatalf("want expired got %s", want)
	}
	// 固定回拨输入，重复 20 次必须完全一致。
	clock.Set(base.Add(10 * 24 * time.Hour))
	for i := 0; i < 20; i++ {
		if got := reasonOf(v.Verify(tok, testFP)); got != want {
			t.Fatalf("iter %d: want %s got %s", i, want, got)
		}
	}
}

func mustWriteFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestTinyRollbackWithinToleranceAfterExpiry 精确复现上报的绕过：
// 时间自然走到到期之后（所有时钟变化都在宽限内），过期被拒；
// 只往回拨几十秒（小于回拨宽限，旧实现会因此放行），新实现必须仍判 expired。
func TestTinyRollbackWithinToleranceAfterExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	iss, v, clock, _ := setup(t, path)
	// 默认宽限：回拨 1 分钟、前跳 24 小时。凭证 30 天后到期。
	expiry := base.Add(30 * 24 * time.Hour)
	tok := issueToken(t, iss, base.Add(-time.Hour), expiry)

	clock.Set(expiry.Add(-30 * time.Second))
	if err := v.Verify(tok, testFP); err != nil { // 到期前 30 秒：通过
		t.Fatalf("before expiry should pass: %v", err)
	}
	clock.Set(expiry.Add(30 * time.Second))
	if got := reasonOf(v.Verify(tok, testFP)); got != ReasonExpired { // 到期后 30 秒：拒绝
		t.Fatalf("want %s got %s", ReasonExpired, got)
	}
	// 只回拨 40 秒（在 1 分钟回拨宽限内），凭证已过期，必须继续拒绝，原因仍是 expired。
	clock.Set(expiry.Add(-10 * time.Second))
	if got := reasonOf(v.Verify(tok, testFP)); got != ReasonExpired {
		t.Fatalf("tiny rollback after expiry must not revive token: want %s got %s", ReasonExpired, got)
	}
}
