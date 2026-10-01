package license

// Reason 是可区分的校验失败原因。
type Reason string

const (
	ReasonOK              Reason = "ok"
	ReasonMalformed       Reason = "malformed_token"
	ReasonBadSignature    Reason = "bad_signature"
	ReasonExpired         Reason = "expired"
	ReasonNotYetValid     Reason = "not_yet_valid"
	ReasonMachineMismatch Reason = "machine_mismatch"
	ReasonRevoked         Reason = "revoked"
	ReasonClockRollback   Reason = "clock_rollback"
	ReasonClockJump       Reason = "clock_jump"
)

// Error 携带可区分的失败原因。
type Error struct {
	Reason Reason
	Detail string
}

func (e *Error) Error() string { return string(e.Reason) + ": " + e.Detail }
