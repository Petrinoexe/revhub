package sub

import (
	"encoding/base64"
	"strings"
	"testing"

	"revhub/internal/model"
)

func TestLinksContainRealityParams(t *testing.T) {
	st := model.Demo()
	links := Links(st, st.Clients[0])
	if len(links) != 1 {
		t.Fatalf("ожидалась одна ссылка, получено %d", len(links))
	}
	l := links[0]
	for _, want := range []string{"vless://", "security=reality", "pbk=", "sid=", "type=tcp", "flow=xtls-rprx-vision"} {
		if !strings.Contains(l, want) {
			t.Errorf("в ссылке нет %q:\n%s", want, l)
		}
	}
	if !strings.Contains(l, "hub.example.com:443") {
		t.Errorf("адрес узла потерялся:\n%s", l)
	}
}

func TestTLSLinkUsesCertificateName(t *testing.T) {
	st := model.Demo()
	in := &st.Inbounds[0]
	in.Security, in.CertSource, in.Domain, in.IP = "tls", "acme", "vpn.example.com", ""
	in.SNI = ""
	st.Nodes[0].PublicAddr = "203.0.113.9:443"
	links := Links(st, st.Clients[0])
	if len(links) != 1 || !strings.Contains(links[0], "sni=vpn.example.com") {
		t.Fatalf("клиент не получил имя TLS-сертификата: %v", links)
	}
}

func TestSelfSignedSourceDisablesCAValidation(t *testing.T) {
	st := model.Demo()
	in := &st.Inbounds[0]
	in.Security, in.CertSource, in.Domain, in.IP = "tls", "selfsigned", "", "203.0.113.9"
	in.SNI, in.SelfSigned = "", false
	links := Links(st, st.Clients[0])
	if len(links) != 1 || !strings.Contains(links[0], "allowInsecure=1") || !strings.Contains(links[0], "sni=203.0.113.9") {
		t.Fatalf("selfsigned-ссылка неполна: %v", links)
	}
}

func TestDisabledClientGetsNothing(t *testing.T) {
	st := model.Demo()
	st.Clients[0].Enabled = false
	if got := Links(st, st.Clients[0]); len(got) != 0 {
		t.Errorf("выключенный клиент не должен получать ссылки, получено %v", got)
	}
}

func TestPayloadIsBase64(t *testing.T) {
	st := model.Demo()
	p := Payload(Links(st, st.Clients[0]))
	raw, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		t.Fatalf("payload не base64: %v", err)
	}
	if !strings.HasPrefix(string(raw), "vless://") {
		t.Errorf("payload = %q", raw)
	}
}
