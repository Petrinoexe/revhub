// Package store — хранилище состояния. MVP: один JSON-файл, один писатель,
// атомарная замена через rename. Интерфейс отделён, чтобы переезд на SQLite
// не задел остальной код (см. docs/DECISIONS.md, ADR-1).
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"revhub/internal/fsperm"
	"revhub/internal/model"
)

type Store struct {
	path string
	mu   sync.RWMutex
	st   model.State
}

func Open(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(b, &s.st); err != nil {
			return nil, fmt.Errorf("состояние %s: %w", path, err)
		}
		s.st.Normalize()
	case errors.Is(err, os.ErrNotExist):
		s.st = model.State{Version: model.StateVersion}
		if err := s.persist(); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	return s, nil
}

// Snapshot отдаёт копию состояния (глубокая копия через JSON — дёшево при
// нашем размере и исключает гонки на слайсах).
func (s *Store) Snapshot() model.State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, _ := json.Marshal(s.st)
	var cp model.State
	_ = json.Unmarshal(b, &cp)
	return cp
}

// Replace проверяет и сохраняет новое состояние.
func (s *Store) Replace(st model.State) error {
	st.Normalize()
	if err := st.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.st
	s.st = st
	if err := s.persist(); err != nil {
		s.st = prev
		return err
	}
	return nil
}

// Patch применяет изменение к состоянию, валидирует и сохраняет.
// Используется фоновыми задачами (статусы узлов) и точечными правками.
func (s *Store) Patch(fn func(*model.State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := s.st
	b, _ := json.Marshal(cp)
	var next model.State
	if err := json.Unmarshal(b, &next); err != nil {
		return err
	}
	if err := fn(&next); err != nil {
		return err
	}
	next.Normalize()
	if err := next.Validate(); err != nil {
		return err
	}
	prev := s.st
	s.st = next
	if err := s.persist(); err != nil {
		s.st = prev
		return err
	}
	return nil
}

func (s *Store) persist() error {
	b, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	// Права — у прежнего файла: apply-local и CLI пишут от root, а читает
	// состояние непривилегированная панель (иначе «permission denied» на старте).
	perm := fsperm.Of(s.path)
	tmp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := perm.Apply(name); err != nil {
		return err
	}
	return os.Rename(name, s.path)
}
