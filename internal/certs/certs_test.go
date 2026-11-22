package certs

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSelfSignedIP(t *testing.T) {
	dir := t.TempDir()
	res, err := SelfSigned(Options{Hosts: []string{"203.0.113.7", "vpn.example.com"}, Days: 30,
		Prefix: filepath.Join(dir, "tls/server")})
	if err != nil {
		t.Fatal(err)
	}
	if res.Pin == "" || len(res.Pin) != 44 {
		t.Errorf("пин должен быть base64 от sha256 (44 символа), получено %q", res.Pin)
	}
	if len(res.IPs) != 1 || res.IPs[0] != "203.0.113.7" {
		t.Errorf("IP не попал в SAN: %+v", res.IPs)
	}
	if len(res.DNSNames) != 1 || res.DNSNames[0] != "vpn.example.com" {
		t.Errorf("домен не попал в SAN: %+v", res.DNSNames)
	}
	info, err := os.Stat(res.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("ключ с правами %v, ожидалось 0600", info.Mode().Perm())
	}
	if !info.ModTime().Before(time.Now().Add(time.Minute)) {
		t.Error("время файла подозрительное")
	}
}

// Пин должен совпадать с тем, что посчитает openssl по этому же файлу.
func TestPinMatchesCertBytes(t *testing.T) {
	dir := t.TempDir()
	res, err := SelfSigned(Options{Hosts: []string{"198.51.100.9"}, Prefix: filepath.Join(dir, "c")})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(res.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("не PEM")
	}
	sum := sha256.Sum256(block.Bytes)
	want := base64.StdEncoding.EncodeToString(sum[:])
	if want != res.Pin {
		t.Errorf("пин %q не совпал с прямым подсчётом %q", res.Pin, want)
	}
}

func TestDescribe(t *testing.T) {
	dir := t.TempDir()
	res, err := SelfSigned(Options{Hosts: []string{"192.0.2.10"}, Days: 10, Prefix: filepath.Join(dir, "x")})
	if err != nil {
		t.Fatal(err)
	}
	info, err := Describe(res.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	if !info.SelfIssued {
		t.Error("сертификат должен опознаваться как самоподписанный")
	}
	if info.DaysLeft < 8 || info.DaysLeft > 10 {
		t.Errorf("дней осталось %d, ожидалось ~9", info.DaysLeft)
	}
	if info.Pin != res.Pin {
		t.Error("Describe вернул другой пин")
	}
}

func TestBadHosts(t *testing.T) {
	if _, err := SelfSigned(Options{}); err == nil {
		t.Error("пустой список хостов должен отвергаться")
	}
	if _, err := SelfSigned(Options{Hosts: []string{"  "}}); err == nil {
		t.Error("пустой хост должен отвергаться")
	}
}

func TestPinRejectsGarbage(t *testing.T) {
	f := filepath.Join(t.TempDir(), "nope.pem")
	os.WriteFile(f, []byte("hello"), 0o600)
	if _, _, err := Pin(f); err == nil || !strings.Contains(err.Error(), "PEM") {
		t.Errorf("ожидалась ошибка про PEM, получено %v", err)
	}
}
