package license

import "time"

// Clock 抽象时间来源，便于测试注入。
type Clock interface {
	Now() time.Time
}

// SystemClock 使用系统时间。
type SystemClock struct{}

// Now 返回当前系统时间。
func (SystemClock) Now() time.Time { return time.Now() }
