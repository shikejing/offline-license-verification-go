# 离线软件授权凭证（License）签发与校验

纯本地进程内运行的离线授权凭证签发与校验库。不依赖任何网络或外部服务，
凭证与机器指纹绑定，具备防复制、防篡改、时钟回拨/跳变识别、撤销持久化与
并发安全能力。

## 1. 威胁模型与设计要点

| 威胁 | 应对 |
| --- | --- |
| 凭证被复制到其他机器 | 凭证绑定目标机器指纹（`mid`），换机校验失败 |
| 凭证内容被改写（有效期、授权范围、机器绑定） | Ed25519 签名覆盖全部载荷字节，任一字段改动即整体失效 |
| 时钟回拨（把时间拨回有效期内） | 持久化时钟高水位标记（HWM），回拨超出宽限期即拒绝 |
| 时钟向前跳变 | 跳变超出限额即拒绝，且不采信跳变后的时间 |
| 凭证被撤销 | 撤销列表持久化，重启不丢失；撤销后校验确定失败 |
| 多协程并发校验/撤销 | 互斥锁串行化，相同输入结果一致，无数据竞争（`-race` 通过） |

## 2. 凭证格式

凭证是一个字符串，结构为 `LIC1.<payload>.<signature>`：

```
LIC1.eyJ2IjoxLCJqaWQiOi... . MEUCIQ...
```

- `LIC1`：版本前缀；
- `payload`：Base64URL（无填充）编码的 JSON 载荷；
- `signature`：Base64URL（无填充）编码的 Ed25519 签名，签名对象为
  **payload 的原始字节**（即 JSON 规范编码后的字节），载荷与签名不可分割。

载荷 JSON 字段（字段顺序固定，保证签名确定性）：

```json
{
  "v": 1,
  "jti": "随机唯一凭证ID（用于撤销）",
  "iss": "签发者标识（可选）",
  "iat": 1748779200,
  "nbf": 1748779200,
  "exp": 1780315200,
  "scope": ["read", "write"],
  "mid": "目标机器指纹 SHA-256 十六进制"
}
```

- `iat` / `nbf` / `exp`：Unix 秒级时间戳，分别为签发时间、生效时间、过期时间；
- `scope`：授权范围（功能/权限名列表），校验时可要求必须包含某范围；
- `mid`：机器指纹，由 `/etc/machine-id`（或 `/var/lib/dbus/machine-id`）、
  主机名、所有已启用非回环网卡的 MAC 地址组合后做 SHA-256 得到，全程离线读取。

签发使用 Ed25519 私钥，校验内置对应公钥。私钥离开签发进程即无法伪造凭证；
没有密钥的情况下修改载荷会导致签名校验失败。

## 3. 校验语义

调用 `Verifier.Verify(token)` 时，按以下**确定顺序**检查，任一失败立即返回
**可区分的失败原因**（`Result.Reason` 为机器可读码，`error` 为对应哨兵错误，
可用 `errors.Is` 判定）：

1. **签名/格式**：`malformed`（凭证无法解析）或 `invalid_signature`
   （签名不符或载荷被篡改）→ `ErrMalformed` / `ErrInvalidSignature`；
2. **机器绑定**：凭证 `mid` 与本机指纹不一致 → `machine_mismatch`
   （`ErrMachineMismatch`），常量时间比较；
3. **时钟回拨**：当前时间 < 高水位标记 − 回拨宽限期 → `clock_rollback`
   （`ErrClockRollback`）；
4. **时钟前跳**：当前时间 > 高水位标记 + 前跳限额 → `clock_forward_jump`
   （`ErrClockForwardJump`）；
5. **未生效**：当前时间 < `nbf` → `not_yet_valid`（`ErrNotYetValid`）；
6. **已过期**：当前时间 ≥ `exp` → `expired`（`ErrExpired`）；
7. **已撤销**：凭证 ID 在撤销列表中 → `revoked`（`ErrRevoked`），
   结果中携带撤销时间与原因；
8. **授权范围**：要求的 scope 不在凭证中 → `scope_not_granted`
   （`ErrScopeNotGranted`，仅 `VerifyScope` 检查）。

通过全部检查后 `Result.Valid == true`，`Reason == "ok"`。
`Result` 始终携带 `CheckedAt`（校验时间）、`MachineID`（本机指纹）与
可读的 `Message`，便于审计追溯。

### 时钟高水位标记（HWM）

- 状态文件持久化观测到的**最大时间戳**，只单调递增、绝不回退；
- 每次校验只要时钟通过了第 3、4 项 sanity 检查，无论凭证最终是否有效
  （过期、撤销、未生效），都会把 HWM 推进到当前时间并原子落盘；
- 因此：凭证过期后把时钟拨回有效期内仍会被识别（回拨），无法"复活"凭证；
- 宽限策略默认值：回拨宽限 `5 分钟`（容忍 NTP 小幅校时），前跳限额
  `30 天`（可通过 `WithRollbackGrace` / `WithForwardJumpLimit` 配置）；
- 前跳被拒绝时**不采纳**跳变后的时间（HWM 保持为真实时间），攻击者无法
  通过一次前跳把所有人锁死在未来；回拨被拒绝时同样不采纳回拨时间。

### 状态文件格式

状态文件（默认路径由 `NewVerifier` 指定，首次使用时创建）：

```json
{
  "version": 1,
  "last_seen_unix": 1748779200,
  "revoked": {
    "<jti>": { "at": 1748800000, "reason": "terms of service violation" }
  }
}
```

- 写入采用"临时文件 + fsync + 原子 rename"，崩溃不会产生半写文件；
- 撤销记录包含撤销时间与原因，重启后撤销与 HWM 均持续生效。

## 4. 并发语义

- `Issuer` 无线程安全问题（每次签发独立）；
- `Verifier` 的全部状态读取与修改（校验、撤销、HWM 推进、落盘）由互斥锁
  串行化，多协程并发校验无数据竞争（`go test -race` 通过）；
- 并发撤销与校验时，校验要么观察到撤销（`revoked`）要么观察到撤销前状态
  （`ok`），结果确定；`Revoke` 返回后，后续校验必然为 `revoked`。

## 5. 使用示例

```go
import "github.com/shikejing/offline-license-verification-go/license"

// 签发方：保管私钥
pub, priv, _ := license.GenerateKeyPair()
issuer := license.NewIssuer(priv, "my-company")
fp, _ := license.MachineFingerprint()
token, _ := issuer.Issue(license.Claims{
    MachineID: fp,
    Scope:     []string{"feature-a"},
    // ID / IssuedAt / NotBefore / ExpiresAt 留空时自动补全：
    // 随机 jti、当前时间、1 年有效期
})

// 校验方：内置公钥，全程离线
verifier, _ := license.NewVerifier(pub, "/var/lib/myapp/license-state.json")
res, err := verifier.Verify(token)
if err != nil {
    // errors.Is(err, license.ErrExpired) / ErrMachineMismatch /
    // ErrClockRollback / ErrRevoked / ... 可区分具体原因
    fmt.Println("拒绝：", res.Reason, res.Message)
}

// 要求授权范围
res, err = verifier.VerifyScope(token, "feature-a")

// 撤销（持久化，重启不失效）
_ = verifier.Revoke(licenseID, "盗版/退款")
```

测试中可通过 `WithClock`（注入时钟）、`WithFingerprint`（注入机器指纹）
确定性地模拟过期、回拨、换机等场景，无需修改系统时间。

## 6. 测试覆盖

`license/license_test.go` 覆盖：有效凭证、换机不匹配、过期、未生效、
时钟回拨（宽限内/宽限外）、前向跳变、过期后回拨无法复活凭证、
载荷/签名/截断/乱码篡改、错误公钥、授权范围、撤销、撤销重启后仍生效、
HWM 重启后仍生效、50 协程并发校验、40 协程并发撤销/校验、签发默认值。
所有测试可重复运行，并发用例通过 `go test -race` 验证。
