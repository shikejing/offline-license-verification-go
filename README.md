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
| `expired` | 超过到期时间 + `ExpiryGracePeriod`，或此前已在可信时间下被确认过期（见下） |
| `machine_mismatch` | 机器指纹与绑定信息不符（换机/复制/改写绑定） |
| `clock_rollback` | 本地时间回拨超过 `RollbackTolerance` |
| `clock_jump` | 本地时间向前跳变超过 `ForwardJumpTolerance` |
| `not_yet_valid` | 未到生效起始时间 |

检查顺序固定为：结构/签名 → 撤销 → **过期墓碑** → 读取时间并做时钟异常检查
（通过后立即推进高水位）→ 机器绑定 → 有效期。因此同一张凭证配同一个
时间输入，无论校验多少次、多少 goroutine/进程并发，结果都一致且可复现。

## 本机对时间的认知如何推进

校验器在状态文件中维护一个已观测可信本地时间的**高水位** `last_seen`，
它是“本机对当前时间的认知”，遵循三条铁律：

1. **只前进、不后退**。取值永远是 `max(旧高水位, 本次读数)`。
2. **任何一次校验只要读到了时间，认知就只能前进**。一次读数先通过时钟
   异常检查，通过后**无论随后的凭证判定成功还是失败**（机器不符、未生效、
   过期……），都会立即把高水位推进并持久化。一次被拒绝的校验不会让之前
   已确认的时间点丢失，也不可能把它改写成更早的值。
3. **不可信读数不被采纳**。回拨/前跳超出宽限期的读数在时钟检查阶段就被
   挡下：既不推进高水位，也不写任何过期结论。因此一次向前跳变被拒后，
   本机认知不会被带到未来；把时间恢复到正常值，未过期凭证仍正常通过。

宽限期内的正常抖动（小幅回拨/前进）放行。尚未到达“读取时间”阶段就失败
的校验（结构损坏、签名错误、已撤销、已留过期墓碑）不触碰时间认知——它们
根本没有使用时间。

### 为什么还要“过期墓碑”

仅靠单调高水位无法堵住一个绕过：在有效期**之后**、且以超过前跳宽限的方式
观测时间时，该读数会被判为 `clock_jump` 而不推进认知；此后把时间调回
有效窗口就会重新通过。物理世界的时间只进不退，因此**只要曾在某个可信
时间读数下确认一张凭证过期，这个结论就是永久成立的**，与之后的时钟回拨、
失败校验、进程重启都无关。

为此状态文件额外持久化一个 `expired` 集合（过期墓碑）：

- 仅当某次读数**通过时钟检查**、且确实超过到期时间（含宽限期）时，才把
  凭证 ID 写入 `expired` 并落盘；时钟异常读数绝不会误写墓碑。
- 墓碑在检查顺序中位于时钟检查**之前**。于是凭证一旦确认过期，即便把
  本机时间回拨回有效窗口，也稳定返回 `expired`，而不会被 `clock_rollback`
  等原因掩盖——过期失败与时钟类失败始终可区分。
- 墓碑只增不清，没有任何接口可以撤销它（与撤销列表相互独立）。

### 时间异常与凭证自身失败的关系

- **时间异常**（`clock_rollback` / `clock_jump`）针对的是“本机时间这个
  输入不可信”，它不改变时间认知，也不下达任何关于凭证有效期的结论。
- **凭证自身失败**（`expired` / `not_yet_valid` / `machine_mismatch` …）
  只可能在时间读数已被采信之后出现；它们不影响时间认知的单调推进。
- 两类原因彼此独立、稳定可区分：同一张凭证 + 同一个时间输入，多次校验
  返回的 `Reason` 必然相同。

## 持久化、并发与状态兼容

撤销列表、高水位与过期墓碑存放于同一 JSON 状态文件：

```json
{
  "revoked": ["license-id-1"],
  "last_seen": "2026-06-15T08:00:00Z",
  "expired": ["license-id-2"]
}
```

- **原子且抗中断**：每次写入都在同目录生成**唯一命名**的临时文件，
  `write → fsync → rename`（并尽力 fsync 目录）。进程在写入中途崩溃或被
  杀死时，正式状态文件要么是旧的完整版本、要么是新的完整版本，绝不会
  出现半截/损坏内容；未被 rename 的孤立临时文件不影响读取。
- **多进程并发**：状态文件旁附带一个 `.lock` 文件，写事务通过
  `flock(2)` 跨进程排他锁串行化（Windows 等无 flock 的平台退化为仅
  进程内锁 + 原子落盘）。事务在锁内**重新读取磁盘并合并**：高水位取
  `max`、集合取并集，因此多个进程并发读写不会丢失彼此的更新。
- **进程内并发**：所有方法可在 `-race` 下并发调用；“读高水位 → 时钟判定
  → 推进/写墓碑”在同一临界区内完成。
- **向后/向前兼容**：旧版本状态文件只有 `revoked`、`last_seen`，缺少
  `expired`（或将来出现任何未知字段）时按零值/忽略处理，等同于首次运行，
  无需人工迁移；旧的撤销语义保持不变。

## 测试

```sh
go test -race ./...
```

除既有用例外，新增用例直接覆盖本次堵住的绕过与相关不变量
（见 `rollback_attack_test.go`）：

| 用例 | 验证内容 |
|---|---|
| `TestExpiredThenRollbackIsRejected` | 过期后把时间回拨回有效窗口仍被拒，原因稳定为 `expired`，多次结果一致 |
| `TestFailedVerificationsPreserveTimeKnowledge` | 机器不符/未生效等失败后高水位仍前进；读时间前的失败不移动认知；回拨仍被识别 |
| `TestForwardJumpIsolation` | 前跳被拒后高水位与墓碑均不被污染，时间恢复后未过期凭证正常通过 |
| `TestConstraintsSurviveRestart` | 过期墓碑与高水位跨重启保留，多次重启 + 回拨仍返回 `expired` |
| `TestInterleavedSuccessAndFailureConcurrency` | 成功/失败/墓碑写入在单调时间线上高并发交错，结果确定、认知只前进 |
| `TestTwoStoresConcurrentWritesDoNotLoseState` | 两个进程各自打开同一状态文件并发写，跨进程锁 + 重读合并不丢失高水位 |
| `TestStateFileIsNeverTruncatedOrCorrupted` | 高强度并发写后状态文件仍是完整 JSON，且无残留临时文件 |
| `TestLegacyStateFileWithoutExpiredFieldLoads` | 旧状态文件直接可读、撤销语义保留，新字段首次写入后往返一致 |
| `TestFutureExtraFieldsAreIgnored` | 未知字段被忽略，不影响已知字段加载 |
