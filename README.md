# offline-license-verification-go

纯本地进程内的离线软件授权凭证签发与校验库。校验不依赖网络或任何外部服务，
凭证绑定机器指纹，能识别时钟回拨/跳变、凭证复制与篡改，撤销状态持久化、重启后仍生效。

## 快速开始

```go
// 签发方（一次性生成密钥对，私钥保密，公钥随软件分发）
pub, priv, _ := license.GenerateKey()

issuer := license.NewIssuer(priv)
tok, _ := issuer.Issue(license.IssueRequest{
    Subject:   "customer-a",
    Scope:     []string{"feature-x"},
    NotBefore: time.Now(),
    ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
    Machine:   license.CurrentFingerprint(), // 绑定目标机器
})

// 校验方（被授权机器上）
store, _ := license.OpenStore("/var/lib/myapp/license-state.json")
v := license.NewVerifier(pub, store, license.Options{
    RollbackTolerance:    time.Minute,   // 允许的最大时钟回拨
    ForwardJumpTolerance: 24 * time.Hour, // 允许的最大向前跳变
    ExpiryGracePeriod:    0,              // 到期宽限期
})
err := v.Verify(tok, license.CurrentFingerprint()) // nil 表示通过

// 撤销（立即持久化，重启后仍生效）
v.Revoke(licenseID)
```

## 凭证格式

凭证为两段式字符串：`base64url(payload) "." base64url(signature)`。

- **payload**：载荷的规范化 JSON（字段顺序固定、时间统一为 UTC），包含：
  | 字段 | 含义 |
  |---|---|
  | `id` | 凭证唯一 ID（撤销依据） |
  | `subject` | 被授权主体 |
  | `scope` | 授权范围（特性列表） |
  | `issued_at` / `not_before` / `expires_at` | 签发时间 / 生效时间 / 到期时间 |
  | `machine_hash` | 机器指纹的 SHA-256（hostname + machine-id + 排序后的 MAC） |
  | `nonce` | 随机数，保证凭证唯一性 |
- **signature**：对 payload 规范化字节的 Ed25519 签名。

解析时强制规范化重编码比对：签名所见即校验所用，任何字段被改写、
重排或附加都会使整体校验失败，不存在“部分字段仍被接受”的情况。

## 校验语义

`Verify` 按固定顺序检查，失败时返回 `*license.Error`，其 `Reason` 可区分：

| Reason | 含义 |
|---|---|
| `malformed_token` | 编码或结构非法 |
| `bad_signature` | 签名与载荷不匹配（含篡改） |
| `revoked` | 凭证已被撤销 |
| `machine_mismatch` | 机器指纹与绑定信息不符（换机/复制/改写绑定） |
| `clock_rollback` | 本地时间回拨超过 `RollbackTolerance` |
| `clock_jump` | 本地时间向前跳变超过 `ForwardJumpTolerance` |
| `not_yet_valid` | 未到生效起始时间 |
| `expired` | 超过到期时间 + `ExpiryGracePeriod` |

### 时钟异常策略：时间认知只前进、不回退

校验器在状态文件中维护已观测本地时间的**高水位**（high-water mark），
它代表“本机已经确认走到过的最晚时间”，语义是**单调只增**：

1. 每次校验先读取当前本地时间 `now` 与持久化高水位 `last_seen`。
2. 先用高水位做**已确认过期**判定：若 `last_seen > expires_at + 宽限期`，
   说明历史上已经有一个受信任的时间点见过这张凭证过期，直接返回 `expired`。
   这一判定**先于**时钟异常检查——因此把时钟回拨到有效期窗口内，
   得到的稳定原因是 `expired`（凭证事实），而不是 `clock_rollback`（时钟事实），
   两者可以明确区分，过期凭证无法靠回拨“复活”。
3. 再识别时钟异常：`now` 相对 `last_seen` 回拨或前跳超出各自宽限期，
   返回 `clock_rollback` / `clock_jump`。**异常时间既不信任也不落盘**，
   高水位保持不变；把时钟恢复到宽限以内的正常值后，未过期凭证照常通过，
   时间认知不会被一次异常跳宽带偏。
4. 时间一旦通过时钟检查被信任，**无论后续凭证自身的检查是否通过**
   （未生效、过期等），高水位都会推进到 `max(last_seen, now)` 并持久化。
   即一次被拒绝的校验也不会让已确认的时间点丢失，更不可能把它改写得更早。
5. 最后才做凭证自身的 `not_yet_valid` / `expired` 判定。
   时钟异常与凭证自身失败是两条相互独立的路径，各自有稳定的 `Reason`。

边界说明：

- 宽限期内的正常抖动（小幅回拨/前跳）视为正常时间，照常推进认知。
- 正常使用中时间本来就会走到凭证到期之后（前跳宽限内的自然流逝），
  因此到期被确认是必然生效的；随后任何回拨都无法解除过期。
- 相同凭证 + 相同时间输入，多次、多进程校验结果一致且可复现。

### 撤销与持久化

撤销列表与高水位存放于同一 JSON 状态文件。状态目录下另有一个
`state.json.lock` 锁文件，所有读-改-写事务都在**跨进程排他文件锁
（flock）**内完成：事务开始时先从磁盘重新载入最新状态，再判断、再落盘，
因此多个校验进程/多个 `StateStore` 句柄并发读写不会互相覆盖丢失更新。

落盘采用崩溃安全的原子序列：写入**唯一命名**的临时文件 → `fsync` 文件 →
`rename` 覆盖正式文件 → `fsync` 目录。写入中途失败或进程被中断时，
磁盘上只可能保留上一份完整状态或新的完整状态，不会出现半截/损坏文件；
事务失败时内存改动一并丢弃，下次事务重新从磁盘对齐。

进程重启后撤销与高水位都仍然生效。撤销完成后所有校验稳定返回 `revoked`。

状态文件向后兼容：缺少字段（例如旧文件没有 `last_seen`）按零值/首次运行
处理，出现新版本的未知字段直接忽略，重新加载即可，**无需人工迁移**，
撤销语义保持不变。

### 并发安全

`Verifier`/`StateStore` 全部方法可并发调用（`-race` 通过）。
进程内由互斥锁串行化，进程间由文件锁串行化，“读高水位→判定→写高水位”
是一个原子事务，相同输入的校验结果一致且可复现。

## 测试

```sh
go test -race ./...          # 功能与并发（建议多跑：-count=N）
```

针对时间回拨绕过的安全场景（见 `license/clock_security_test.go`）：

| 测试 | 覆盖行为 |
|---|---|
| `TestExpiredThenRollbackStaysRejected` | 过期后把时钟调回有效期窗口，凭证持续被拒且原因稳定为 `expired`；重启后仍拒绝 |
| `TestExpiryReasonSeparatedFromClockRollback` | 同一下高水位下，过期凭证与未过期凭证分别得到 `expired` / `clock_rollback`，原因可区分 |
| `TestFailedVerificationsAdvanceClockKnowledge` | `not_yet_valid`/`expired` 等失败校验同样推进高水位；任何失败/异常都不能把认知改写小 |
| `TestForwardJumpIsolation` | 异常前跳被拒后高水位不动，时间恢复到正常值后未过期凭证正常通过 |
| `TestClockKnowledgePersistsAcrossRestart` | 高水位跨重启保留，重启后回拨仍识别为已过期 |
| `TestConcurrentSuccessAndFailureInterleaving` | 成功/失败/撤销/纯读路径并发交错：同输入结果一致、状态文件随时可读、高水位不回退 |
| `TestConcurrentRevokeAcrossProcesses` / `TestObserveConcurrentAcrossProcesses` | 多个独立句柄（模拟多进程）并发撤销/观测时间，无丢失更新 |
| `TestLegacyStateFileLoads` | 缺字段/含未知字段的旧状态文件免迁移加载，撤销保留 |
| `TestStateFileNeverLeftHalfWritten` | 残留半截临时文件不影响加载，反复落盘后正式文件始终完整 |
| `TestDeterministicSameInputSameResult` | 同一凭证同一时间输入多次校验结果一致 |

此外仍覆盖：有效凭证、过期、到期宽限、未生效、时钟回拨、时钟前跳、
载荷/签名篡改、结构损坏、换机、绑定信息部分改写、撤销及重启后持久化、
并发校验与并发撤销、结果可复现性。
