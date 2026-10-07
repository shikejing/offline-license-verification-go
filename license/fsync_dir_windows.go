//go:build windows

package license

// syncDir 在非 Unix 平台为空操作，rename 本身保证状态文件原子可见。
func syncDir(dir string) {}
