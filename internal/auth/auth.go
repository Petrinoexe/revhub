// Package auth — пароль панели и сессионные cookie.
//
// Пароль хранится как PBKDF2-HMAC-SHA256 (соль + счётчик итераций), cookie —
// подписанный HMAC токен без серверного состояния, чтобы перезапуск панели не
// выкидывал админа. Файл credentials.json лежит рядом с состоянием, права 0600.
package auth

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	CookieName  = "revhub_session"
	iterations  = 210_000
	keyLength   = 32
	SessionTTL  = 12 * time.Hour
	minPassword = 8
)

// ErrNotConfigured — пароль ещё не задан (панель обязана отказать).
var ErrNotConfigured = errors.New("пароль панели не задан: выполните `revhub passwd`")

type Credentials struct {
	User    string    `json:"user"`
	Salt    string    `json:"salt"` // base64
	Hash    string    `json:"hash"` // base64, PBKDF2(password)
	Iter    int       `json:"iter"`
	Secret  string    `json:"secret"` // base64, ключ подписи cookie
	Updated time.Time `json:"updated"`
}

func pathFor(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), "credentials.json")
}

// Load читает файл учётных данных. ErrNotConfigured, если файла нет.
func Load(statePath string) (*Credentials, error) {
	b, err := os.ReadFile(pathFor(statePath))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotConfigured
	}
	if err != nil {
		return nil, err
	}
	var c Credentials
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("credentials.json: %w", err)
	}
	if c.Hash == "" || c.Secret == "" {
		return nil, ErrNotConfigured
	}
	return &c, nil
}

// Create задаёт (или меняет) пароль и сохраняет файл атомарно.
func Create(statePath, user, password string) (*Credentials, error) {
	if len([]rune(password)) < minPassword {
		return nil, fmt.Errorf("пароль короче %d символов", minPassword)
	}
	if user == "" {
		user = "admin"
	}
	salt := make([]byte, 16)
	secret := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	h, err := pbkdf2.Key(sha256.New, password, salt, iterations, keyLength)
	if err != nil {
		return nil, err
	}
	c := &Credentials{
		User: user, Salt: b64(salt), Hash: b64(h), Iter: iterations,
		Secret: b64(secret), Updated: time.Now().UTC(),
	}
	if err := c.save(statePath); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Credentials) save(statePath string) error {
	p := pathFor(statePath)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".cred-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	if err := os.Chmod(name, 0o600); err != nil {
		return err
	}

	// панель работает отдельным пользователем: группе нужен доступ на чтение
	// (passwd запускают от root, и без этого панель перестаёт видеть креды)
	if os.Geteuid() == 0 {
		if gr, err := user.LookupGroup("revhub"); err == nil {
			if gid, err := strconv.Atoi(gr.Gid); err == nil {
				_ = os.Chown(name, 0, gid)
				_ = os.Chmod(name, 0o640)
			}
		}
	}
	return os.Rename(name, p)
}

// Verify сверяет пользователя и пароль в постоянном времени.
func (c *Credentials) Verify(user, password string) bool {
	if subtle.ConstantTimeCompare([]byte(user), []byte(c.User)) != 1 {
		return false
	}
	salt, err1 := base64.StdEncoding.DecodeString(c.Salt)
	want, err2 := base64.StdEncoding.DecodeString(c.Hash)
	if err1 != nil || err2 != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, c.Iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// NewSession возвращает подписанный токен: base64(payload).base64(hmac).
func (c *Credentials) NewSession(now time.Time) string {
	exp := now.Add(SessionTTL).Unix()
	payload := c.User + "|" + strconv.FormatInt(exp, 10)
	return payload + "|" + b64(c.sign(payload))
}

// ValidSession проверяет подпись и срок.
func (c *Credentials) ValidSession(token string, now time.Time) bool {
	i := strings.LastIndex(token, "|")
	if i < 0 {
		return false
	}
	payload, sig := token[:i], token[i+1:]
	got, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	if !hmac.Equal(got, c.sign(payload)) {
		return false
	}
	parts := strings.Split(payload, "|")
	if len(parts) != 2 || parts[0] != c.User {
		return false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return false
	}
	return now.Unix() < exp
}

func (c *Credentials) sign(payload string) []byte {
	key, _ := base64.StdEncoding.DecodeString(c.Secret)
	m := hmac.New(sha256.New, key)
	m.Write([]byte(payload))
	return m.Sum(nil)
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// Limiter — грубый счётчик неудачных попыток входа по адресу.
type Limiter struct {
	mu       sync.Mutex
	attempts map[string]*entry
	max      int
	window   time.Duration
}

type entry struct {
	n     int
	until time.Time
}

func NewLimiter(max int, window time.Duration) *Limiter {
	return &Limiter{attempts: map[string]*entry{}, max: max, window: window}
}

// Allow сообщает, можно ли пробовать пароль с этого адреса.
func (l *Limiter) Allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.attempts[key]
	if !ok {
		return true
	}
	if now.After(e.until) {
		delete(l.attempts, key)
		return true
	}
	return e.n < l.max
}

// Fail фиксирует неудачу; Reset вызывается после успешного входа.
func (l *Limiter) Fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.attempts[key]
	if !ok || now.After(e.until) {
		l.attempts[key] = &entry{n: 1, until: now.Add(l.window)}
		return
	}
	e.n++
}

func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, key)
}

// Wait — сколько ждать до следующей попытки (для текста ошибки).
func (l *Limiter) Wait(key string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e, ok := l.attempts[key]; ok {
		if d := e.until.Sub(now); d > 0 {
			return d.Round(time.Second)
		}
	}
	return 0
}
