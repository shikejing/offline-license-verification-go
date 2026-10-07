package license

// fileLock 是对状态文件的跨进程排他锁抽象。
// 多个进程同时打开同一个状态文件时，写事务需要串行化，避免丢失彼此的更新。
type fileLock interface {
	// lock 获取排他锁（必要时阻塞），返回的释放函数在事务结束时调用。
	lock() (unlock func(), err error)
	// close 释放底层句柄。
	close() error
}

// newFileLock 在与状态文件同目录创建/打开一个伴随锁文件。
// 空路径（纯内存模式）返回 nil。
func newFileLock(statePath string) (fileLock, error) {
	if statePath == "" {
		return nil, nil
	}
	return platformFileLock(statePath)
}
