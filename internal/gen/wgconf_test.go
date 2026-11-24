package gen

import (
	"strings"
	"testing"

	"revhub/internal/model"
)

func clientNetState() model.State {
	st := model.State{
		Version: model.StateVersion,
		Nodes:   []model.Node{{ID: "hub", Name: "Хаб", PublicAddr: "vpn.example.com:2096"}},
		Inbounds: []model.Inbound{{
			ID: "in-wg", NodeID: "hub", Tag: "wg", Kind: model.InboundWireGuard,
			Listen: "0.0.0.0", Port: 51820, Enabled: true,
		}},
		Clients: []model.Client{
			{Email: "alice@revhub", Enabled: true, Inbounds: []string{"in-wg"}},
			{Email: "bob@revhub", Enabled: true, Inbounds: []string{"in-wg"}},
		},
	}
	st.Normalize()
	return st
}

// Серверный конфиг клиентской сети: одна подсеть, пиры /32, форвардинг и NAT.
func TestClientWGConfDirectEgress(t *testing.T) {
	st := clientNetState()
	in := st.Inbounds[0]
	conf, err := ClientWGConf(st, in, "hub")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Address = 10.88.0.1/24",
		"ListenPort = 51820",
		"net.ipv4.ip_forward=1",
		"iptables -I FORWARD -i %i -j ACCEPT",
		"masquerade",
		"AllowedIPs = 10.88.0.2/32",
		"AllowedIPs = 10.88.0.3/32",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("в конфиге интерфейса нет %q:\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "0.0.0.0/0") {
		t.Error("серверу не нужен default в туннель")
	}
	// приватный ключ клиента не должен попадать в конфиг сервера
	if strings.Contains(conf, st.Clients[0].WireGuard["in-wg"].PrivateKey) {
		t.Error("приватный ключ клиента в конфиге узла")
	}
}

// Только включённые клиенты; без них интерфейс не поднимается.
func TestClientWGConfSkipsInactive(t *testing.T) {
	st := clientNetState()
	st.Clients[1].Enabled = false
	conf, err := ClientWGConf(st, st.Inbounds[0], "hub")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(conf, st.Clients[1].WireGuard["in-wg"].PublicKey) {
		t.Error("выключенный клиент попал в конфиг")
	}
	st.Clients[0].Enabled = false
	if _, err := ClientWGConf(st, st.Inbounds[0], "hub"); err == nil {
		t.Fatal("без клиентов конфиг не должен рендериться")
	}
}

// Выход через туннель: маршрут по источнику вместо NAT.
func TestClientWGConfTunnelEgress(t *testing.T) {
	st := clientNetState()
	st.Tunnels = []model.Tunnel{{
		ID: "t1", Name: "eu", Kind: model.TunnelWG, Enabled: true,
		FromNode: "hub", ToNode: "hub", Subnet: "10.77.1.0/30", ListenPort: 51900, Mark: 300,
	}}
	st.Normalize()
	st.Inbounds[0].Egress = "tun:eu"
	conf, err := ClientWGConf(st, st.Inbounds[0], "hub")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(conf, "ip rule add from 10.88.0.0/24 lookup 300 pref 32000") {
		t.Errorf("нет маршрута в туннель:\n%s", conf)
	}
	if strings.Contains(conf, "masquerade") {
		t.Error("при выходе в туннель NAT делает выходной узел, не хаб")
	}
}
