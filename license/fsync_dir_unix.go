//go:build !windows

package license

import (
	"os"
	"syscall"
)

// syncDir 强制把目录项变更（rename）刷盘，失败尽力而为不阻断主流程。
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = syscall.Fsync(int(d.Fd()))
		_ = d.Close()
	}
}
