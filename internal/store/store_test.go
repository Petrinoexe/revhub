package store

import (
	"os"
	"path/filepath"
	"testing"

	"revhub/internal/model"
)

// Права файла состояния переживают запись: этим ломался старт панели, когда
// состояние правили от root (apply-local, revhub panel).
func TestPersistKeepsMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := st.Patch(func(s *model.State) error {
		s.Nodes = []model.Node{{ID: "node-1", PublicAddr: "vpn.example.com:2096"}}
		s.Panel = &model.PanelConfig{Listen: "127.0.0.1:2096"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("после записи режим = %o, ожидался 640", fi.Mode().Perm())
	}
}
