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
	Revoked  []string  `json:"revoked"`
	LastSeen time.Time `json:"last_seen"`
}

// StateStore 持久化撤销列表与时间高水位，进程重启后仍生效。
// 所有方法可并发调用；写操作通过 tmp+rename 原子落盘。
type StateStore struct {
	mu      sync.RWMutex
	path    string
	revoked map[string]struct{}
	lastSeen time.Time
}

// OpenStore 打开（必要时创建）状态文件。
func OpenStore(path string) (*StateStore, error) {
	s := &StateStore{path: path, revoked: map[string]struct{}{}}
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		var st state
		if err := json.Unmarshal(b, &st); err != nil {
			return nil, fmt.Errorf("load state %s: %w", path, err)
		}
		for _, id := range st.Revoked {
			s.revoked[id] = struct{}{}
		}
		s.lastSeen = st.LastSeen
	case errors.Is(err, fs.ErrNotExist):
		// 首次使用，空状态即可。
	default:
		return nil, fmt.Errorf("read state %s: %w", path, err)
	}
	return s, nil
}

// flush 在持有写锁时调用，将当前状态原子写入磁盘。
// path 为空时为纯内存模式，跳过落盘。
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
	if dir := filepath.Dir(s.path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// IsRevoked 报告凭证是否已撤销。
func (s *StateStore) IsRevoked(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.revoked[id]
	return ok
}

// Revoke 记录撤销并立即持久化。
func (s *StateStore) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[id] = struct{}{}
	return s.flush()
}

// LastSeen 返回已观测的最大本地时间。
func (s *StateStore) LastSeen() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastSeen
}

// Observe 记录一次时间观测：高水位只前进不回退，并持久化。
func (s *StateStore) Observe(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t.After(s.lastSeen) {
		s.lastSeen = t.UTC()
		return s.flush()
	}
	return nil
}
