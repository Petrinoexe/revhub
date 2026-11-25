package fsperm

import (
	"os"
	"path/filepath"
	"testing"
)

// Замена файла не должна отбирать права у того, кто его читает: root пишет
// состояние, панель читает — иначе «permission denied» на старте.
func TestOfKeepsExistingMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	perm := Of(path)
	if perm.Mode != 0o640 {
		t.Fatalf("режим = %o, ожидался 640", perm.Mode)
	}
	tmp := filepath.Join(dir, "new.json")
	if err := os.WriteFile(tmp, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := perm.Apply(tmp); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(tmp); fi.Mode().Perm() != 0o640 {
		t.Errorf("после Apply режим = %o", fi.Mode().Perm())
	}
}

func TestOfNewFileFollowsDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := Of(filepath.Join(dir, "state.json")).Mode; got != 0o600 {
		t.Errorf("личный каталог: режим = %o, ожидался 600", got)
	}
	shared := t.TempDir()
	if err := os.Chmod(shared, 0o770); err != nil {
		t.Fatal(err)
	}
	if got := Of(filepath.Join(shared, "state.json")).Mode; got != 0o660 {
		t.Errorf("каталог группы: режим = %o, ожидался 660 (панель должна прочитать)", got)
	}
}
