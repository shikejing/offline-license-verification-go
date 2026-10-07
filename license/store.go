package license

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"
)

// state 是持久化到磁盘的结构。
// 新增或缺失字段都按零值处理：旧版本写入的状态文件无需迁移即可继续读取。
type state struct {
	Revoked  []string  `json:"revoked"`
	LastSeen time.Time `json:"last_seen"`
}

// StateStore 持久化撤销列表与时间高水位，进程重启后仍生效。
// 所有方法可并发、可跨进程调用：磁盘上的读-改-写在同一把文件锁内完成，
// 写操作采用唯一临时文件 + fsync + rename 原子落盘，中断时只会留下
// 上一份完整状态或新的完整状态，不会出现半截文件。
type StateStore struct {
	mu       sync.Mutex // 进程内串行化；跨进程由 flock 串行化
	path     string
	lockFile *os.File
	revoked  map[string]struct{}
	lastSeen time.Time
}

// OpenStore 打开（必要时创建）状态文件。
func OpenStore(path string) (*StateStore, error) {
	s := &StateStore{path: path, revoked: map[string]struct{}{}}
	if path != "" {
		if err := s.openLock(); err != nil {
			return nil, err
		}
	}
	if err := s.load(); err != nil {
		_ = s.closeLock()
		return nil, err
	}
	return s, nil
}

// openLock 打开与状态文件配套的锁文件，用于跨进程互斥。
func (s *StateStore) openLock() error {
	if dir := filepath.Dir(s.path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("prepare state dir %s: %w", dir, err)
		}
	}
	f, err := os.OpenFile(s.path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open lock for state %s: %w", s.path, err)
	}
	s.lockFile = f
	return nil
}

func (s *StateStore) closeLock() error {
	if s.lockFile == nil {
		return nil
	}
	err := s.lockFile.Close()
	s.lockFile = nil
	return err
}

// Close 释放底层锁文件。纯内存模式无操作。
func (s *StateStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeLock()
}

// lock 获取跨进程排他锁。纯内存模式直接返回。
func (s *StateStore) lock() error {
	if s.lockFile == nil {
		return nil
	}
	return syscall.Flock(int(s.lockFile.Fd()), syscall.LOCK_EX)
}

// unlock 释放跨进程排他锁。
func (s *StateStore) unlock() {
	if s.lockFile != nil {
		_ = syscall.Flock(int(s.lockFile.Fd()), syscall.LOCK_UN)
	}
}

// load 从磁盘重新载入完整状态到内存。文件不存在时视为首次运行。
// 调用方必须已持有 s.mu；磁盘模式下还应持有文件锁。
func (s *StateStore) load() error {
	if s.path == "" {
		return nil
	}
	b, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil // 首次使用，空状态即可
	}
	if err != nil {
		return fmt.Errorf("read state %s: %w", s.path, err)
	}
	var st state
	if err := json.Unmarshal(b, &st); err != nil {
		return fmt.Errorf("load state %s: %w", s.path, err)
	}
	s.revoked = map[string]struct{}{}
	for _, id := range st.Revoked {
		s.revoked[id] = struct{}{}
	}
	s.lastSeen = st.LastSeen.UTC()
	return nil
}

// txn 在进程内锁与跨进程文件锁保护下执行 fn。
// fn 执行前内存状态已与磁盘最新提交对齐；磁盘模式下 fn 返回后，
// 只要 changed 为 true 就原子落盘一次。fn 中的改动只在写盘成功后
// 对后续事务可见（下次事务会再次从磁盘重载）。
func (s *StateStore) txn(mutate func() bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.lock(); err != nil {
		return fmt.Errorf("lock state %s: %w", s.path, err)
	}
	defer s.unlock()
	if err := s.load(); err != nil {
		return err
	}
	changed := false
	if mutate != nil {
		changed = mutate()
	}
	if changed {
		if err := s.flush(); err != nil {
			// 写盘失败：丢弃本次内存改动，强制下一个从事务从磁盘恢复，
			// 绝不把未落盘的状态当作已确认事实。
			_ = s.load()
			return err
		}
	}
	return nil
}

// read 在锁保护下从磁盘最新状态读取一个值。
func (s *StateStore) read(fn func()) {
	_ = s.txn(func() bool { fn(); return false })
}

// flush 在持锁状态下将当前状态原子写入磁盘：
// 唯一临时文件 -> fsync 文件 -> rename -> fsync 目录，
// 任何一步被中断都不会产生半截状态文件。
func (s *StateStore) flush() error {
	if s.path == "" {
		return nil
	}
	ids := make([]string, 0, len(s.revoked))
	for id := range s.revoked {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	b, err := json.Marshal(&state{Revoked: ids, LastSeen: s.lastSeen.UTC()})
	if err != nil {
		return err
	}
	var randBytes [8]byte
	if _, err := rand.Read(randBytes[:]); err != nil {
		return fmt.Errorf("generate temp name: %w", err)
	}
	dir := filepath.Dir(s.path)
	tmp := filepath.Join(dir, ".state-"+hex.EncodeToString(randBytes[:])+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create temp state: %w", err)
	}
	tmpName := f.Name()
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write temp state: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("sync temp state: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close temp state: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("replace state: %w", err)
	}
	syncDir(dir)
	return nil
}

// syncDir 对目录做一次 fsync，确保 rename 结果在崩溃后仍落盘。
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// IsRevoked 报告凭证是否已撤销（对其它进程刚刚提交的撤销立即可见）。
func (s *StateStore) IsRevoked(id string) bool {
	var ok bool
	s.read(func() { _, ok = s.revoked[id] })
	return ok
}

// Revoke 记录撤销并立即持久化，重复撤销是幂等的。
func (s *StateStore) Revoke(id string) error {
	return s.txn(func() bool {
		if _, ok := s.revoked[id]; ok {
			return false
		}
		s.revoked[id] = struct{}{}
		return true
	})
}

// LastSeen 返回已观测的最大本地时间（高水位）。
func (s *StateStore) LastSeen() time.Time {
	var t time.Time
	s.read(func() { t = s.lastSeen })
	return t
}

// Observe 记录一次被信任的时间观测：高水位只前进、不回退，
// 并在推进时持久化。传入更早的时间绝不会把高水位改写小。
func (s *StateStore) Observe(t time.Time) error {
	t = t.UTC()
	return s.txn(func() bool {
		if t.After(s.lastSeen) {
			s.lastSeen = t
			return true
		}
		return false
	})
}
