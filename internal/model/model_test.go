package model

import (
	"strings"
	"testing"
)

func TestDemoValid(t *testing.T) {
	st := Demo()
	if err := st.Validate(); err != nil {
		t.Fatalf("демо-состояние невалидно: %v", err)
	}
}

func TestValidateCatchesBrokenRefs(t *testing.T) {
	st := Demo()
	st.Routes[1].Outbound = "tun:nope"
	err := st.Validate()
	if err == nil || !strings.Contains(err.Error(), "tun:nope") {
		t.Fatalf("ожидалась ошибка про несуществующий исходящий, получено %v", err)
	}
}

func TestValidateCatchesExpiredInbound(t *testing.T) {
	st := Demo()
	st.Clients[0].Inbounds = []string{"missing"}
	if err := st.Validate(); err == nil {
		t.Fatal("ссылка клиента на несуществующий инбаунд должна ловиться")
	}
}

func TestSubnetAddrs(t *testing.T) {
	from, to, err := SubnetAddrs("10.77.5.0/30")
	if err != nil {
		t.Fatal(err)
	}
	if from != "10.77.5.1" || to != "10.77.5.2" {
		t.Errorf("адреса = %s/%s", from, to)
	}
	if _, _, err := SubnetAddrs("10.77.5.0/24"); err == nil {
		t.Error("/24 должен отвергаться: в туннеле ровно два адреса")
	}
}

func TestNextSubnetSkipsUsed(t *testing.T) {
	st := Demo()
	if got := st.NextSubnet(); got != "10.77.2.0/30" {
		t.Errorf("следующая подсеть = %s, ожидалась 10.77.2.0/30", got)
	}
}

func TestWGKeysRoundTrip(t *testing.T) {
	priv, pub, err := GenWGKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(priv) != 44 || len(pub) != 44 {
		t.Errorf("ключи WG должны быть 44 символа base64, получено %d/%d", len(priv), len(pub))
	}
}

func TestRealityKeysAreURLSafe(t *testing.T) {
	priv, pub, err := GenRealityKeys()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{priv, pub} {
		if len(k) != 43 {
			t.Errorf("reality-ключ должен быть 43 символа base64url без паддинга, получено %d", len(k))
		}
		if strings.ContainsAny(k, "+/=") {
			t.Errorf("reality-ключ содержит недопустимые символы: %s", k)
		}
	}
}

func TestValidateRequiresIPForLECertificate(t *testing.T) {
	st := Demo()
	in := &st.Inbounds[0]
	in.Security, in.CertSource = "tls", "acmeip"
	in.Domain, in.IP, in.CertFile, in.KeyFile = "", "", "", ""
	err := st.Validate()
	if err == nil || !strings.Contains(err.Error(), "ip") {
		t.Fatalf("ожидалась ошибка про ip, получено %v", err)
	}
	in.IP = "203.0.113.7"
	if err := st.Validate(); err != nil {
		t.Errorf("с заполненным ip состояние должно быть валидным: %v", err)
	}
}

func TestValidateWireGuardDNS(t *testing.T) {
	st := Demo()
	st.Inbounds = append(st.Inbounds, Inbound{
		ID: "in-wg", NodeID: "hub", Tag: "wg", Kind: InboundWireGuard,
		Listen: "0.0.0.0", Port: 51830, Enabled: true,
	})
	st.Clients[0].Inbounds = append(st.Clients[0].Inbounds, "in-wg")
	st.Normalize()
	if err := st.Validate(); err != nil {
		t.Fatalf("инбаунд WireGuard должен быть валиден: %v", err)
	}
	wg := st.Inbounds[1].WireGuard
	if wg.DNS != DefaultWireGuardDNS {
		t.Errorf("DNS по умолчанию = %q, ожидалось %q", wg.DNS, DefaultWireGuardDNS)
	}
	wg.DNS = "1.1.1.1, dns.example.com"
	if err := st.Validate(); err == nil || !strings.Contains(err.Error(), "DNS") {
		t.Errorf("ожидалась ошибка про DNS, получено %v", err)
	}
	wg.DNS = "8.8.8.8, 8.8.4.4"
	if err := st.Validate(); err != nil {
		t.Errorf("список IP должен приниматься: %v", err)
	}
}

func TestSecondTunnelGetsUniqueAddressAndPort(t *testing.T) {
	st := Demo()
	second := st.Tunnels[0]
	second.ID = "tun-second"
	second.Name = "second"
	second.FromAddr, second.ToAddr = "", ""
	second.Mark++
	st.Tunnels = append(st.Tunnels, second)
	st.Normalize()
	got := st.Tunnels[1]
	if got.FromAddr != "10.88.0.201" || got.ToAddr != "10.88.0.251" {
		t.Fatalf("адреса второго туннеля: %s/%s", got.FromAddr, got.ToAddr)
	}
	if got.ListenPort != 51821 {
		t.Fatalf("порт второго слушателя = %d", got.ListenPort)
	}
	if err := st.Validate(); err != nil {
		t.Fatalf("два разведённых туннеля должны быть валидны: %v", err)
	}
}

func TestValidateRejectsDuplicateTunnelEndpoints(t *testing.T) {
	st := Demo()
	second := st.Tunnels[0]
	second.ID, second.Name = "tun-second", "second"
	second.Mark++
	st.Tunnels = append(st.Tunnels, second)
	if err := st.Validate(); err == nil || !strings.Contains(err.Error(), "уже используется") {
		t.Fatalf("дубли адресов/порта приняты: %v", err)
	}
}

func TestClientEgressMustStartAtEveryInboundNode(t *testing.T) {
	st := Demo()
	st.Inbounds = append(st.Inbounds, Inbound{ID: "in-wg-exit", NodeID: "exit-eu", Tag: "wg-exit", Kind: InboundWireGuard, Enabled: true})
	st.Clients[0].Inbounds = append(st.Clients[0].Inbounds, "in-wg-exit")
	st.Clients[0].Egress = "tun:eu" // туннель начинается на hub, не на exit-eu
	st.Normalize()
	if err := st.Validate(); err == nil || !strings.Contains(err.Error(), "exit-eu") {
		t.Fatalf("личный выход с чужого узла принят: %v", err)
	}
}

func TestValidateRejectsControlCharactersInConfigFields(t *testing.T) {
	cases := map[string]func(*State){
		"client email": func(s *State) { s.Clients[0].Email = "alice\n[Interface]\nPostUp = true" },
		"node name":    func(s *State) { s.Nodes[0].Name = "hub\nbad" },
		"node address": func(s *State) { s.Nodes[0].PublicAddr = "hub.example.com\rbad" },
		"inbound path": func(s *State) { s.Inbounds[0].Path = "/ws\nbad" },
		"tunnel name":  func(s *State) { s.Tunnels[0].Name = "eu\nbad" },
		"route name":   func(s *State) { s.Routes[0].Name = "rule\nbad" },
		"DNS zone":     func(s *State) { s.DNS = &DNSConfig{Root: "vpn.internal\nbad"} },
		"panel listen": func(s *State) { s.Panel.Listen = "127.0.0.1:2096\nbad" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			st := Demo()
			mutate(&st)
			err := st.Validate()
			if err == nil || !strings.Contains(err.Error(), "управляющие символы") {
				t.Fatalf("поле с управляющими символами принято: %v", err)
			}
		})
	}
}
