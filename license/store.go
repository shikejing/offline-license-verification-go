package license

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// state 是持久化到磁盘的结构。
type state struct {
	// Revoked 为已撤销凭证 ID 集合，语义与旧版本一致。
	Revoked []string `json:"revoked"`
	// LastSeen 是本机已观测到的最大可信本地时间（高水位）。
	LastSeen time.Time `json:"last_seen"`
	// Expired 是“已在可信时间读数下确认过期”的凭证 ID 墓碑集合。
	// 物理时间只进不退，一旦确认过期，该结论永久有效，与之后的时钟回拨/
	// 失败校验/进程重启无关。旧版本状态文件没有该字段，缺失即空，按首次运行处理。
	Expired []string `json:"expired,omitempty"`
}

// StateStore 持久化撤销列表、时间高水位与过期墓碑，进程重启后仍生效。
// 所有方法可并发调用；写操作在“跨进程排他锁 + 进程内互斥锁”内重读合并，
// 再以独立临时文件 fsync+rename 原子落盘，崩溃或中断不会留下半截状态。
type StateStore struct {
	mu       sync.RWMutex
	path     string
	lock     fileLock
	revoked  map[string]struct{}
	expired  map[string]struct{}
	lastSeen time.Time
}

// OpenStore 打开（必要时创建）状态文件。
// 旧版本状态文件（缺少 expired 等新增字段）可直接读取，无需迁移。
func OpenStore(path string) (*StateStore, error) {
	s := &StateStore{
		path:    path,
		revoked: map[string]struct{}{},
		expired: map[string]struct{}{},
	}
	if path != "" {
		if dir := filepath.Dir(path); dir != "" {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return nil, fmt.Errorf("prepare state dir: %w", err)
			}
		}
		lk, err := newFileLock(path)
		if err != nil {
			return nil, fmt.Errorf("open state lock: %w", err)
		}
		s.lock = lk
	}
	if err := s.loadInitial(); err != nil {
		return nil, err
	}
	return s, nil
}

// loadInitial 读取磁盘上的现有状态；文件不存在视为首次运行的空状态。
func (s *StateStore) loadInitial() error {
	b, err := os.ReadFile(s.path)
	switch {
	case err == nil:
		st, err := decodeState(b)
		if err != nil {
			return fmt.Errorf("load state %s: %w", s.path, err)
		}
		s.applyState(st)
	case errors.Is(err, fs.ErrNotExist):
		// 首次使用，空状态即可。
	default:
		return fmt.Errorf("read state %s: %w", s.path, err)
	}
	return nil
}

// decodeState 解析状态字节，新增/缺失字段一律容忍：缺失即零值，
// 无法识别的字段被忽略，因此新旧版本状态文件可相互直接读取。
func decodeState(b []byte) (state, error) {
	var st state
	if err := json.Unmarshal(b, &st); err != nil {
		return st, err
	}
	return st, nil
}

// applyState 在持有写锁时调用，将磁盘状态合并进内存视图。
// 高水位取 max：任何来源都不得让本机时间认知后退；集合做并集。
func (s *StateStore) applyState(st state) {
	for _, id := range st.Revoked {
		s.revoked[id] = struct{}{}
	}
	for _, id := range st.Expired {
		s.expired[id] = struct{}{}
	}
	if st.LastSeen.After(s.lastSeen) {
		s.lastSeen = st.LastSeen.UTC()
	}
}

// persist 在已持有进程内写锁与跨进程排他锁时调用，将当前状态原子写入磁盘。
// path 为空时为纯内存模式，跳过落盘。
func (s *StateStore) persist() error {
	if s.path == "" {
		return nil
	}
	revoked := make([]string, 0, len(s.revoked))
	for id := range s.revoked {
		revoked = append(revoked, id)
	}
	sort.Strings(revoked)
	expired := make([]string, 0, len(s.expired))
	for id := range s.expired {
		expired = append(expired, id)
	}
	sort.Strings(expired)
	b, err := json.Marshal(&state{
		Revoked:  revoked,
		LastSeen: s.lastSeen.UTC(),
		Expired:  expired,
	})
	if err != nil {
		return err
	}
	if dir := filepath.Dir(s.path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	// 每次事务使用独立的临时文件名，配合 fsync + rename：
	// 即便写入中途崩溃，留在磁盘上的也只是一个未被 rename 的孤立临时文件，
	// 正式状态文件始终指向此前完整的一版，绝不会出现半截内容。
	tmp, err := os.CreateTemp(filepath.Dir(s.path), "."+filepath.Base(s.path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return err
	}
	cleanup = false
	// 目录项的变更也需落盘，尽力而为（部分文件系统不支持）。
	syncDir(filepath.Dir(s.path))
	return nil
}

// mutate 在“跨进程排他锁 + 进程内写锁”内重读磁盘、应用变更、原子落盘。
// fn 基于合并后的最新内存视图做修改，返回 dirty 表示是否产生了需要持久化的变更。
func (s *StateStore) mutate(fn func() (dirty bool, err error)) error {
	unlock, err := s.beginTransaction()
	if err != nil {
		return err
	}
	defer unlock()

	dirty, err := fn()
	if err != nil {
		return err
	}
	if !dirty {
		return nil
	}
	return s.persist()
}

// beginTransaction 先取跨进程排他锁，再取进程内写锁，并在锁内重读磁盘，
// 合并其它进程在此期间写入的更新。返回的释放函数按相反顺序解锁。
func (s *StateStore) beginTransaction() (func(), error) {
	var unflock func()
	if s.lock != nil {
		u, err := s.lock.lock()
		if err != nil {
			return nil, fmt.Errorf("acquire state lock: %w", err)
		}
		unflock = u
	}
	s.mu.Lock()
	committed := false
	defer func() {
		if !committed {
			s.mu.Unlock()
			if unflock != nil {
				unflock()
			}
		}
	}()

	if s.path != "" {
		if b, err := os.ReadFile(s.path); err == nil {
			if st, derr := decodeState(b); derr == nil {
				// 重读只做合并（高水位取 max、集合并集），不覆盖内存中的更新。
				s.applyState(st)
			}
			// 若磁盘文件恰好不可读或损坏，则以本进程内存为准继续本次事务，
			// 成功落盘后状态重新收敛。
		}
	}
	committed = true
	return func() {
		s.mu.Unlock()
		if unflock != nil {
			unflock()
		}
	}, nil
}

// IsRevoked 报告凭证是否已撤销。
func (s *StateStore) IsRevoked(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.revoked[id]
	return ok
}

// IsExpired 报告凭证是否已在某次可信时间读数下被确认过期。
func (s *StateStore) IsExpired(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.expired[id]
	return ok
}

// Revoke 记录撤销并立即持久化。
func (s *StateStore) Revoke(id string) error {
	return s.mutate(func() (bool, error) {
		if _, ok := s.revoked[id]; ok {
			return false, nil
		}
		s.revoked[id] = struct{}{}
		return true, nil
	})
}

// MarkExpired 将凭证记入过期墓碑并立即持久化。该记录不可撤销、不可被
// 后续失败校验或时钟回拨清除。
func (s *StateStore) MarkExpired(id string) error {
	return s.mutate(func() (bool, error) {
		if _, ok := s.expired[id]; ok {
			return false, nil
		}
		s.expired[id] = struct{}{}
		return true, nil
	})
}

// LastSeen 返回已观测的最大可信本地时间。
func (s *StateStore) LastSeen() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastSeen
}

// Observe 记录一次“通过了时钟异常检查”的时间读数。
// 本机时间认知只能前进不能后退：高水位取 max，且无论随后的凭证校验
// 成功还是失败（过期/未生效等）都必须落盘，一次拒绝不得丢失已确认的时间点。
// 不前进的读数返回 dirty=false，但仍会在事务内重读合并其它进程的推进。
func (s *StateStore) Observe(t time.Time) error {
	t = t.UTC()
	return s.mutate(func() (bool, error) {
		if !t.After(s.lastSeen) {
			return false, nil
		}
		s.lastSeen = t
		return true, nil
	})
}

// Close 释放跨进程锁句柄。
func (s *StateStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock != nil {
		return s.lock.close()
	}
	return nil
}
