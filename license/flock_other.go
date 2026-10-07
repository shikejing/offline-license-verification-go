//go:build windows

package license

// nopFileLock 用于暂不支持跨进程建议锁的平台：进程内仍由互斥锁串行化，
// 原子 tmp+rename 落盘保证状态文件不会写坏。
type nopFileLock struct{}

func platformFileLock(statePath string) (fileLock, error) { return nopFileLock{}, nil }

func (nopFileLock) lock() (func(), error) { return func() {}, nil }

func (nopFileLock) close() error { return nil }
