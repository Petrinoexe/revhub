// Package certs выпускает самоподписанные сертификаты и считает пиннинги.
//
// Зачем: публичные CA не выдают сертификаты на голый IP, а без TLS нельзя ни
// панель вынести с loopback, ни поднять VLESS с security=tls. Поэтому для IP
// выпускается самоподписанный сертификат с SAN=IP, а клиент проверяет его по
// закреплённому SHA-256 (xray: tlsSettings.pinnedPeerCertificateChainSha256).
package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Options struct {
	Hosts  []string // IP и/или домены; каждый попадёт в SAN
	Days   int      // срок; по умолчанию 3650
	Org    string   // организация в субъекте
	Prefix string   // путь+имя без расширения: <prefix>.crt / <prefix>.key
}

type Result struct {
	CertFile string
	KeyFile  string
	Pin      string // base64(sha256(DER)) — то, что ждёт xray
	NotAfter time.Time
	DNSNames []string
	IPs      []string
}

// SelfSigned выпускает самоподписанный сертификат и пишет .crt/.key (0644/0600).
func SelfSigned(o Options) (*Result, error) {
	if len(o.Hosts) == 0 {
		return nil, fmt.Errorf("нужен хотя бы один хост или IP")
	}
	if o.Days == 0 {
		o.Days = 3650
	}
	if o.Org == "" {
		o.Org = "revhub"
	}
	if o.Prefix == "" {
		o.Prefix = "server"
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{o.Org}, CommonName: first(o.Hosts)},
		NotBefore:             time.Now().Add(-time.Hour), // запас на расхождение часов
		NotAfter:              time.Now().AddDate(0, 0, o.Days),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	res := &Result{NotAfter: tmpl.NotAfter}
	for _, h := range o.Hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			res.IPs = append(res.IPs, ip.String())
			continue
		}
		tmpl.DNSNames = append(tmpl.DNSNames, h)
		res.DNSNames = append(res.DNSNames, h)
	}
	if len(tmpl.IPAddresses) == 0 && len(tmpl.DNSNames) == 0 {
		return nil, fmt.Errorf("ни один хост не разобрался: %v", o.Hosts)
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	res.CertFile = o.Prefix + ".crt"
	res.KeyFile = o.Prefix + ".key"
	if err := writePEM(res.CertFile, "CERTIFICATE", der, 0o644); err != nil {
		return nil, err
	}
	if err := writePEM(res.KeyFile, "EC PRIVATE KEY", keyDER, 0o600); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	res.Pin = base64.StdEncoding.EncodeToString(sum[:])
	return res, nil
}

// Pin считает закреплённый хэш по файлу сертификата и заодно проверяет, что он
// читается как X.509.
func Pin(certFile string) (string, *x509.Certificate, error) {
	b, err := os.ReadFile(certFile)
	if err != nil {
		return "", nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", nil, fmt.Errorf("%s: не PEM-сертификат", certFile)
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(block.Bytes)
	return base64.StdEncoding.EncodeToString(sum[:]), crt, nil
}

type Info struct {
	CertFile   string    `json:"cert_file"`
	NotAfter   time.Time `json:"not_after"`
	DaysLeft   int       `json:"days_left"`
	DNSNames   []string  `json:"dns_names"`
	IPs        []string  `json:"ips"`
	Pin        string    `json:"pin"`
	SelfIssued bool      `json:"self_issued"`
}

// Describe читает сертификат и отдаёт всё, что нужно для отчёта и для клиента.
func Describe(certFile string) (*Info, error) {
	pin, crt, err := Pin(certFile)
	if err != nil {
		return nil, err
	}
	info := &Info{
		CertFile: certFile, NotAfter: crt.NotAfter,
		DaysLeft: int(time.Until(crt.NotAfter).Hours() / 24),
		Pin:      pin, SelfIssued: crt.Subject.String() == crt.Issuer.String(),
	}
	for _, n := range crt.DNSNames {
		info.DNSNames = append(info.DNSNames, n)
	}
	for _, ip := range crt.IPAddresses {
		info.IPs = append(info.IPs, ip.String())
	}
	return info, nil
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	b := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, b, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}
