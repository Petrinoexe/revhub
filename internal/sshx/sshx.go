// Package sshx — минимальный SSH-клиент для установки и управления узлами.
//
// Единственная внешняя зависимость проекта (golang.org/x/crypto/ssh): свой
// SSH-стек — это месяцы работы и дыры. Всё остальное по-прежнему на stdlib.
package sshx

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type Target struct {
	Addr       string // host:port
	User       string
	Password   string
	KeyPEM     []byte
	Passphrase string
	HostKey    string // ожидаемый отпечаток base64(sha256(key)); пусто = TOFU
	Timeout    time.Duration
}

// HostKeyMismatch — сервер ответил другим ключом, чем мы записали при первой
// установке. Соединение обязано прерваться, а не «продолжить на свой риск».
type HostKeyMismatch struct {
	Want, Got string
}

func (e *HostKeyMismatch) Error() string {
	return fmt.Sprintf("ключ хоста не совпал: ожидали %s, получили %s", short(e.Want), short(e.Got))
}

type Client struct {
	c        *ssh.Client
	hostKey  string // фактический отпечаток (для TOFU-записи)
	Addr     string
	DialedAt time.Duration
}

// HostKey — отпечаток ключа сервера, который надо запомнить после установки.
func (c *Client) HostKey() string { return c.hostKey }

// Dial подключается по SSH. Порядок аутентификации: ключ, затем пароль.
func Dial(t Target) (*Client, error) {
	if t.Timeout == 0 {
		t.Timeout = 15 * time.Second
	}
	if t.User == "" {
		t.User = "root"
	}
	var auths []ssh.AuthMethod
	if len(t.KeyPEM) > 0 {
		var signer ssh.Signer
		var err error
		if t.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(t.KeyPEM, []byte(t.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(t.KeyPEM)
		}
		if err != nil {
			return nil, fmt.Errorf("приватный ключ: %w", err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}
	if t.Password != "" {
		auths = append(auths, ssh.Password(t.Password))
	}
	if len(auths) == 0 {
		return nil, fmt.Errorf("нет ни ключа, ни пароля для %s", t.Addr)
	}

	var gotKey string
	cfg := &ssh.ClientConfig{
		User:    t.User,
		Auth:    auths,
		Timeout: t.Timeout,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			sum := sha256.Sum256(key.Marshal())
			gotKey = base64.StdEncoding.EncodeToString(sum[:])
			if t.HostKey != "" && t.HostKey != gotKey {
				return &HostKeyMismatch{Want: t.HostKey, Got: gotKey}
			}
			return nil
		},
	}
	start := time.Now()
	c, err := ssh.Dial("tcp", t.Addr, cfg)
	if err != nil {
		// ssh.Dial заворачивает ошибку хендшейка: разворачиваем свой тип, чтобы
		// вызывающий код мог отличить подмену ключа от сетевой ошибки.
		var mism *HostKeyMismatch
		if errors.As(err, &mism) {
			return nil, mism
		}
		return nil, err
	}
	return &Client{c: c, hostKey: gotKey, Addr: t.Addr, DialedAt: time.Since(start)}, nil
}

func (c *Client) Close() error { return c.c.Close() }

// Run выполняет команду через sh -c и возвращает объединённый вывод.
// Ненулевой код возврата — ошибка с хвостом вывода: иначе на узле остаётся
// «exit status 1» без причины.
func (c *Client) Run(cmd string) (string, error) {
	sess, err := c.c.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	var out bytes.Buffer
	sess.Stdout = &out
	sess.Stderr = &out
	err = sess.Run(cmd)
	res := out.String()
	if err != nil {
		return res, fmt.Errorf("%s: %w: %s", firstLine(cmd), err, tail(res, 400))
	}
	return res, nil
}

// Upload кладёт файл: содержимое идёт через base64, поэтому не зависит от
// наличия scp/sftp на узле, и права выставляются сразу.
func (c *Client) Upload(path string, data []byte, mode os.FileMode) error {
	dir := path
	if i := strings.LastIndex(dir, "/"); i > 0 {
		dir = dir[:i]
	}
	_, err := c.Run(UploadCommand(dir, path, data, mode))
	return err
}

// UploadCommand собирает sh-команду загрузки: без scp/sftp, содержимое через
// base64, права выставляются в том же вызове. Вынесено отдельно, чтобы
// проверять сборку команды тестом, не поднимая SSH-сервер.
func UploadCommand(dir, path string, data []byte, mode os.FileMode) string {
	b64 := base64.StdEncoding.EncodeToString(data)
	var sb strings.Builder
	fmt.Fprintf(&sb, "mkdir -p %s && : > %s && ", shellQuote(dir), shellQuote(path))
	const chunk = 4000
	for i := 0; i < len(b64); i += chunk {
		end := i + chunk
		if end > len(b64) {
			end = len(b64)
		}
		fmt.Fprintf(&sb, "printf %%s %s | base64 -d >> %s && ", shellQuote(b64[i:end]), shellQuote(path))
	}
	fmt.Fprintf(&sb, "chmod %o %s", mode.Perm(), shellQuote(path))
	return sb.String()
}

// Exists проверяет наличие файла или бинаря.
func (c *Client) Exists(path string) bool {
	_, err := c.Run("test -e " + shellQuote(path))
	return err == nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:8] + "…"
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
