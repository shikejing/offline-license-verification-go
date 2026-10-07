//go:build !windows

package license

import (
	"os"
	"path/filepath"
	"syscall"
)

// unixFileLock 基于 flock(2) 的建议性排他锁，锁随文件描述符。
type unixFileLock struct {
	f *os.File
}

func platformFileLock(statePath string) (fileLock, error) {
	lockPath := statePath + ".lock"
	if dir := filepath.Dir(lockPath); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	return &unixFileLock{f: f}, nil
}

func (l *unixFileLock) lock() (func(), error) {
	if err := syscall.Flock(int(l.f.Fd()), syscall.LOCK_EX); err != nil {
		return nil, err
	}
	return func() { _ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN) }, nil
}

func (l *unixFileLock) close() error { return l.f.Close() }
