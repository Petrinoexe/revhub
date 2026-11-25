package sub

import (
	"strings"
	"testing"

	"revhub/internal/model"
)

// wgState — хаб с одним WireGuard-инбаундом и клиентом на нём. Порт в
// public_addr нарочно от панели: WireGuard слушает свой, а не 2096.
func wgState() model.State {
	st := model.State{
		Version: model.StateVersion,
		Nodes:   []model.Node{{ID: "hub", Name: "Хаб", PublicAddr: "hub.example.com:2096"}},
		Inbounds: []model.Inbound{{
			ID: "in-wg", NodeID: "hub", Tag: "wg-hub", Kind: model.InboundWireGuard,
			Listen: "0.0.0.0", Port: 51820, Enabled: true,
		}},
		Clients: []model.Client{{
			ID: "cl-1", Email: "alice@revhub", Enabled: true, Inbounds: []string{"in-wg"},
		}},
	}
	st.Normalize()
	return st
}

func TestWireGuardConfigIsStandard(t *testing.T) {
	st := wgState()
	c := st.Clients[0]
	confs := WireGuardConfigs(st, c)
	if len(confs) != 1 {
		t.Fatalf("ожидался один конфиг, получено %d", len(confs))
	}
	conf := confs[0]
	if conf.Inbound != "in-wg" || conf.Tag != "wg-hub" || conf.File != "alice-revhub-wg-hub.conf" {
		t.Fatalf("неверные метаданные конфига: %+v", conf)
	}
	in := st.Inbounds[0]
	peer := c.WireGuard["in-wg"]
	for _, want := range []string{
		"# revhub: alice@revhub",
		"[Interface]\n",
		"PrivateKey = " + peer.PrivateKey,
		"Address = " + peer.Address,
		"DNS = " + model.DefaultWireGuardDNS,
		"MTU = 1420",
		"[Peer]\n",
		"PublicKey = " + in.WireGuard.PublicKey,
		"PresharedKey = " + peer.PresharedKey,
		"AllowedIPs = 0.0.0.0/0",
		"Endpoint = hub.example.com:51820",
		"PersistentKeepalive = 25",
	} {
		if !strings.Contains(conf.Text, want) {
			t.Errorf("в конфиге нет %q:\n%s", want, conf.Text)
		}
	}
	if !strings.HasSuffix(conf.Text, "\n") {
		t.Error("файл конфига должен заканчиваться переводом строки")
	}
	// Порт панели не должен попасть в Endpoint: клиент дозванивается на инбаунд.
	if strings.Contains(conf.Text, ":2096") {
		t.Errorf("в Endpoint попал порт панели:\n%s", conf.Text)
	}
}

// wg-quick читает формат построчно: комментарий, заголовок секции или
// `Ключ = значение`. Ничего другого в файле быть не может.
func TestWireGuardConfigParsesAsWGQuick(t *testing.T) {
	st := wgState()
	conf := WireGuardConfigs(st, st.Clients[0])[0]
	sections := map[string]map[string]bool{}
	section := ""
	for i, line := range strings.Split(strings.TrimSuffix(conf.Text, "\n"), "\n") {
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
			continue
		case line == "[Interface]" || line == "[Peer]":
			if sections[line] != nil {
				t.Errorf("строка %d: секция %s повторяется", i+1, line)
			}
			section = line
			sections[section] = map[string]bool{}
			continue
		}
		key, value, ok := strings.Cut(line, " = ")
		if !ok || section == "" || key == "" || value == "" {
			t.Fatalf("строка %d не в формате wg-quick: %q", i+1, line)
		}
		if sections[section][key] {
			t.Errorf("строка %d: ключ %s повторяется в %s", i+1, key, section)
		}
		sections[section][key] = true
	}
	for _, want := range []string{"PrivateKey", "Address", "DNS", "MTU"} {
		if !sections["[Interface]"][want] {
			t.Errorf("в [Interface] нет %s", want)
		}
	}
	for _, want := range []string{"PublicKey", "PresharedKey", "AllowedIPs", "Endpoint"} {
		if !sections["[Peer]"][want] {
			t.Errorf("в [Peer] нет %s", want)
		}
	}
}

func TestWireGuardConfigEndpointMatchesLink(t *testing.T) {
	st := wgState()
	confs := WireGuardConfigs(st, st.Clients[0])
	links := Links(st, st.Clients[0])
	if len(confs) != 1 || len(links) != 1 {
		t.Fatalf("ожидались один конфиг и одна ссылка, получено %d и %d", len(confs), len(links))
	}
	if !strings.Contains(links[0], "wireguard://") || !strings.Contains(links[0], "@hub.example.com:51820?") {
		t.Fatalf("ссылка подписки не совпадает с конфигом по адресу:\n%s", links[0])
	}
	if !strings.Contains(confs[0].Text, "Endpoint = hub.example.com:51820\n") {
		t.Fatalf("Endpoint в конфиге не совпадает со ссылкой:\n%s", confs[0].Text)
	}
}

func TestWireGuardLinkAndConfigShareInternalDNS(t *testing.T) {
	st := wgState()
	st.DNS = &model.DNSConfig{Root: "vpn.internal", NodeID: "hub"}
	links := Links(st, st.Clients[0])
	if len(links) != 1 || !strings.Contains(links[0], "dns=10.88.0.1") {
		t.Fatalf("ссылка не получила внутренний DNS: %v", links)
	}
	conf := WireGuardConfigs(st, st.Clients[0])[0].Text
	if !strings.Contains(conf, "DNS = 10.88.0.1\n") {
		t.Fatalf("конфиг и ссылка разошлись по DNS:\n%s", conf)
	}
}

func TestWireGuardConfigDNSOverride(t *testing.T) {
	st := wgState()
	st.Inbounds[0].WireGuard.DNS = "9.9.9.9"
	conf := WireGuardConfigs(st, st.Clients[0])[0]
	if !strings.Contains(conf.Text, "DNS = 9.9.9.9\n") || strings.Contains(conf.Text, "1.1.1.1") {
		t.Errorf("DNS инбаунда не подставился в конфиг:\n%s", conf.Text)
	}
}

func TestWireGuardConfigRequiresActiveClientAndInbound(t *testing.T) {
	cases := map[string]func(*model.State){
		"клиент выключен": func(st *model.State) { st.Clients[0].Enabled = false },
		"клиент истёк": func(st *model.State) {
			st.Clients[0].ExpiresAt = "2000-01-01T00:00:00Z"
		},
		"инбаунд выключен": func(st *model.State) { st.Inbounds[0].Enabled = false },
		"инбаунд без адреса узла": func(st *model.State) {
			st.Nodes[0].PublicAddr = ""
		},
		"инбаунд не привязан": func(st *model.State) {
			st.Clients[0].Inbounds = nil
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			st := wgState()
			mutate(&st)
			st.Normalize()
			if confs := WireGuardConfigs(st, st.Clients[0]); len(confs) != 0 {
				t.Fatalf("конфиг не должен выдаваться: %+v", confs)
			}
		})
	}
}

func TestWireGuardConfigFileName(t *testing.T) {
	c := model.Client{Email: "Иван Петров"}
	if got := fileName(c, "wg e2"); got != "wg-e2.conf" {
		t.Errorf("имя файла = %q, ожидалось wg-e2.conf", got)
	}
	if got := fileName(model.Client{}, ""); got != "client.conf" {
		t.Errorf("имя файла = %q, ожидалось client.conf", got)
	}
}
