// Package secrets — SSH-секреты узлов. Отдельный файл рядом с состоянием:
// state.json уезжает в бэкапы и диффы, пароли туда попадать не должны.
package secrets

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"revhub/internal/fsperm"
)

type Secret struct {
	Password    string `json:"password,omitempty"`
	PrivateKey  string `json:"private_key,omitempty"` // содержимое ключа, не путь
	Passphrase  string `json:"passphrase,omitempty"`
	UpdatedUnix int64  `json:"updated_unix"`
}

type Store struct {
	path string
	mu   sync.RWMutex
	m    map[string]Secret
}

func Open(statePath string) (*Store, error) {
	s := &Store{path: filepath.Join(filepath.Dir(statePath), "secrets.json"), m: map[string]Secret{}}
	b, err := os.ReadFile(s.path)
	switch {
	case err == nil:
		if err := json.Unmarshal(b, &s.m); err != nil {
			return nil, fmt.Errorf("secrets.json: %w", err)
		}
	case errors.Is(err, os.ErrNotExist):
	default:
		return nil, err
	}
	if s.m == nil {
		s.m = map[string]Secret{}
	}
	return s, nil
}

func (s *Store) Get(nodeID string) (Secret, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.m[nodeID]
	return v, ok
}

// Set сохраняет секрет узла и сразу пишет файл (0600).
func (s *Store) Set(nodeID string, v Secret) error {
	v.UpdatedUnix = now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[nodeID] = v
	return s.persist()
}

func (s *Store) Delete(nodeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, nodeID)
	return s.persist()
}

// Has сообщает, есть ли для узла чем аутентифицироваться.
func (s *Store) Has(nodeID string) bool {
	v, ok := s.Get(nodeID)
	if !ok {
		return false
	}
	return v.Password != "" || v.PrivateKey != ""
}

func (s *Store) persist() error {
	b, err := json.MarshalIndent(s.m, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".secrets-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	if err := fsperm.Of(s.path).Apply(name); err != nil {
		return err
	}
	return os.Rename(name, s.path)
}
