package license

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// persistedState is the on-disk state of a Verifier.
type persistedState struct {
	Version  int                      `json:"version"`
	LastSeen int64                    `json:"last_seen_unix"`
	Revoked  map[string]revokedRecord `json:"revoked"`
}

// revokedRecord traces a single revocation.
type revokedRecord struct {
	At     int64  `json:"at"`
	Reason string `json:"reason,omitempty"`
}

// stateStore handles atomic loading and persistence of state.
type stateStore struct {
	path string
}

func newStateStore(path string) *stateStore {
	return &stateStore{path: path}
}

// load reads the state file. A missing file yields a fresh empty state.
func (s *stateStore) load() (persistedState, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return persistedState{Version: 1, Revoked: map[string]revokedRecord{}}, nil
		}
		return persistedState{}, err
	}
	var st persistedState
	if err := json.Unmarshal(data, &st); err != nil {
		return persistedState{}, err
	}
	if st.Version == 0 {
		st.Version = 1
	}
	if st.Revoked == nil {
		st.Revoked = map[string]revokedRecord{}
	}
	return st, nil
}

// persist atomically writes the state file: data goes to a temp file in the
// same directory, is fsynced, then renamed over the target so a crash never
// leaves a partially written state file.
func (s *stateStore) persist(st persistedState) error {
	if st.Revoked == nil {
		st.Revoked = map[string]revokedRecord{}
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".license-state-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		cleanup()
		return err
	}
	return nil
}
