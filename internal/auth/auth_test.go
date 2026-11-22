package auth

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func tmpState(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "state.json")
}

func TestCreateAndVerify(t *testing.T) {
	p := tmpState(t)
	if _, err := Load(p); err != ErrNotConfigured {
		t.Fatalf("без файла должна быть ErrNotConfigured, получено %v", err)
	}
	c, err := Create(p, "admin", "correct-horse")
	if err != nil {
		t.Fatal(err)
	}
	if !c.Verify("admin", "correct-horse") {
		t.Error("верный пароль отвергнут")
	}
	if c.Verify("admin", "correct-horsE") {
		t.Error("неверный пароль принят")
	}
	if c.Verify("root", "correct-horse") {
		t.Error("чужой пользователь принят")
	}
	// пароль не должен лежать в файле открытым текстом
	b, _ := os.ReadFile(filepath.Join(filepath.Dir(p), "credentials.json"))
	if len(b) == 0 || contains(string(b), "correct-horse") {
		t.Error("пароль попал в файл в открытом виде")
	}
	if info, err := os.Stat(filepath.Join(filepath.Dir(p), "credentials.json")); err == nil {
		if info.Mode().Perm() != 0o600 {
			t.Errorf("права файла %v, ожидались 0600", info.Mode().Perm())
		}
	}
}

func TestShortPasswordRejected(t *testing.T) {
	if _, err := Create(tmpState(t), "admin", "1234"); err == nil {
		t.Error("короткий пароль принят")
	}
}

func TestSessions(t *testing.T) {
	c, err := Create(tmpState(t), "admin", "correct-horse")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tok := c.NewSession(now)
	if !c.ValidSession(tok, now) {
		t.Error("свежая сессия невалидна")
	}
	if c.ValidSession(tok, now.Add(SessionTTL+time.Minute)) {
		t.Error("просроченная сессия принята")
	}
	// подмена полезной нагрузки ломает подпись
	if c.ValidSession("admin|9999999999|"+tok[len(tok)-10:], now) {
		t.Error("подделанная сессия принята")
	}
	// после смены пароля старые cookie недействительны (новый секрет)
	c2, err := Create(tmpState(t), "admin", "another-password")
	if err != nil {
		t.Fatal(err)
	}
	if c2.ValidSession(tok, now) {
		t.Error("сессия пережила смену секрета")
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(3, time.Minute)
	now := time.Now()
	for i := 0; i < 3; i++ {
		if !l.Allow("1.2.3.4", now) {
			t.Fatalf("попытка %d заблокирована раньше времени", i+1)
		}
		l.Fail("1.2.3.4", now)
	}
	if l.Allow("1.2.3.4", now) {
		t.Error("после лимита вход должен быть запрещён")
	}
	if !l.Allow("5.6.7.8", now) {
		t.Error("другой адрес не должен страдать")
	}
	if l.Allow("1.2.3.4", now.Add(2*time.Minute)) != true {
		t.Error("окно блокировки не истекло")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
