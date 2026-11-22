package api

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	"revhub/internal/model"
)

func (s *Server) hasPanelTLS() bool {
	return s.LocalNode != "" && s.TLSCert != "" && s.TLSKey != ""
}

// Bind only the certificate configured for this process, on its own node.
func (s *Server) bindPanelTLS(st *model.State) error {
	var cert *x509.Certificate
	for i := range st.Inbounds {
		in := &st.Inbounds[i]
		if in.CertSource != "panel" || in.Kind == model.InboundWireGuard || (in.Security != "tls" && in.Security != "") {
			continue
		}
		if !s.hasPanelTLS() || in.NodeID != s.LocalNode {
			return fmt.Errorf("инбаунд %s: сертификат панели доступен только на её локальном HTTPS-узле", in.Tag)
		}
		if cert == nil {
			pair, err := tls.LoadX509KeyPair(s.TLSCert, s.TLSKey)
			if err != nil {
				return fmt.Errorf("не удалось прочитать пару TLS панели: %w", err)
			}
			cert = pair.Leaf
			now := time.Now()
			if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
				return fmt.Errorf("сертификат панели сейчас недействителен")
			}
		}
		host := ""
		for _, node := range st.Nodes {
			if node.ID == in.NodeID {
				host = node.PublicAddr
				if name, _, err := net.SplitHostPort(host); err == nil {
					host = name
				}
				break
			}
		}
		host = strings.Trim(host, "[]")
		name := host
		if cert.VerifyHostname(name) != nil {
			name = ""
			for _, dns := range cert.DNSNames {
				if !strings.Contains(dns, "*") && cert.VerifyHostname(dns) == nil {
					name = dns
					break
				}
			}

		}
		if host == "" || name == "" {
			return fmt.Errorf("инбаунд %s: публичный адрес узла не подходит для сертификата панели", in.Tag)
		}
		var err error
		in.CertFile, err = filepath.Abs(s.TLSCert)
		if err != nil {
			return err
		}
		in.KeyFile, err = filepath.Abs(s.TLSKey)
		if err != nil {
			return err
		}
		in.SNI = name
		in.SelfSigned = isSelfSigned(cert)
		in.CertSHA256 = ""
		if in.SelfSigned {
			sum := sha256.Sum256(cert.Raw)
			in.CertSHA256 = hex.EncodeToString(sum[:])
		}
	}
	return nil
}

func isSelfSigned(cert *x509.Certificate) bool {
	return string(cert.RawSubject) == string(cert.RawIssuer) && cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}
