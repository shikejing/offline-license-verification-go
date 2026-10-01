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

### 时钟异常策略

校验器在状态文件中维护已观测本地时间的**高水位**（只前进、不回退）。
每次校验将当前时间与高水位比对：回拨或前跳超出各自宽限期即拒绝，
绝不直接信任异常时间；宽限期内的正常抖动放行。校验通过才推进高水位，
失败不污染状态。

### 撤销与持久化

撤销列表与高水位存放于同一 JSON 状态文件，写入采用 tmp+rename 原子落盘，
进程重启后撤销仍然生效。撤销与校验并发时结果确定：撤销完成后所有校验
稳定返回 `revoked`。

### 并发安全

`Verifier`/`StateStore` 全部方法可并发调用（`-race` 通过）。
“读高水位→判定→写高水位”在同一临界区内完成，相同输入的校验结果
一致且可复现。

## 测试

```sh
go test -race ./...
```

覆盖：有效凭证、过期、到期宽限、未生效、时钟回拨、时钟前跳、
载荷/签名篡改、结构损坏、换机、绑定信息部分改写、撤销及重启后持久化、
并发校验与并发撤销、结果可复现性。
