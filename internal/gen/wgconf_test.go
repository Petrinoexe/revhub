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

// apply.sh должен заранее сказать, что адрес занят, и снимать наши
// интерфейсы, оставшиеся без конфига (переименовали тег).
func TestApplyScriptChecksBusyAddress(t *testing.T) {
	st := clientNetState()
	iface := st.Inbounds[0].WGInterface()
	files, err := Artifacts(st, "hub")
	if err != nil {
		t.Fatal(err)
	}
	var script string
	for _, f := range files {
		if f.Name == "apply.sh" {
			script = f.Content
		}
	}
	if !strings.Contains(script, "уже занят интерфейсом") {
		t.Error("нет предварительной проверки занятого адреса")
	}
	if !strings.Contains(script, "ss -lunH") {
		t.Error("нет проверки занятого UDP-порта: ядро биндит порт при `ip link set up`, " +
			"и занятый порт даёт «Address already in use» при свободном адресе")
	}
	if !strings.Contains(script, "grep '^wgc-'") {
		t.Error("нет снятия наших интерфейсов без конфига")
	}
	if !strings.Contains(script, iface) {
		t.Errorf("скрипт не упоминает интерфейс %s", iface)
	}
}

// Xray должен перезапуститься ДО подъёма WG: старая конфигурация может
// держать UDP-порт клиентского инбаунда, и тогда `ip link set up` падает.
func TestXrayRestartsBeforeWireGuard(t *testing.T) {
	st := clientNetState()
	st.Inbounds = append(st.Inbounds, model.Inbound{
		ID: "in-vless", NodeID: "hub", Tag: "vless", Kind: model.InboundVLESS,
		Listen: "0.0.0.0", Port: 443, Enabled: true, Security: "none",
	})
	st.Clients[0].Inbounds = append(st.Clients[0].Inbounds, "in-vless")
	files, err := Artifacts(st, "hub")
	if err != nil {
		t.Fatal(err)
	}
	var script string
	for _, f := range files {
		if f.Name == "apply.sh" {
			script = f.Content
		}
	}
	xray := strings.Index(script, "systemctl restart xray")
	wg := strings.Index(script, "wg-quick up")
	if xray < 0 || wg < 0 {
		t.Fatalf("в скрипте нет перезапуска Xray (%d) или подъёма WG (%d)", xray, wg)
	}
	if xray > wg {
		t.Error("Xray перезапускается после WG-интерфейсов: занятый порт даёт «Address already in use»")
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
	// По входному интерфейсу, а не по адресу источника: `from` увёл бы в
	// туннель и собственный трафик узла с адреса 10.88.0.1.
	if !strings.Contains(conf, "ip rule add iif %i lookup 300 pref 32000") {
		t.Errorf("нет маршрута в туннель по входному интерфейсу:\n%s", conf)
	}
	if strings.Contains(conf, "ip rule add from") {
		t.Error("правило по источнику перехватывает трафик самого узла")
	}
	// Пир-пир должен остаться в своей сети: в таблице туннеля нужен маршрут
	// на подсеть через %i, иначе клиент-клиент уедет в туннель.
	if !strings.Contains(conf, "ip -4 route replace 10.88.0.0/24 dev %i table 300") {
		t.Errorf("нет маршрута на клиентскую сеть в таблице туннеля:\n%s", conf)
	}
	// Хаб подменяет клиентский адрес на адрес туннеля: выход — «тупой шлюз»,
	// его WireGuard выбрасывает пакеты с чужими источниками по AllowedIPs.
	// NAT в интернет делает по-прежнему выходной узел.
	if !strings.Contains(conf, `add rule ip revhub_`) ||
		!strings.Contains(conf, `ip saddr 10.88.0.0/24 oifname`) {
		t.Errorf("нет подмены источника при выходе в туннель:\n%s", conf)
	}
	if strings.Contains(conf, "oifname != %i masquerade") || strings.Contains(conf, `oifname != "%i" masquerade`) {
		t.Error("в интернет должен NAT'ить выходной узел, а не хаб")
	}
}

// Застрявший default в таблице метки от нашей же прошлой попытки нельзя
// принимать за чужой: иначе туннель не поднимается никогда, а клиенты молча
// уходят напрямую. Чужой default (ручной wg0) по-прежнему повод отказаться.
func TestTunnelPreUpDistinguishesOwnDefault(t *testing.T) {
	st := clientNetState()
	st.Tunnels = []model.Tunnel{{
		ID: "t1", Name: "eu", Kind: model.TunnelWG, Enabled: true,
		FromNode: "hub", ToNode: "hub", Subnet: "10.77.1.0/30", ListenPort: 51900, Mark: 300,
		FromKeyPriv: zeroKey, FromKeyPub: zeroKey, ToKeyPriv: zeroKey, ToKeyPub: zeroKey,
	}}
	st.Normalize()
	conf, err := WGConfig(st, st.Tunnels[0], "hub")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"снят устаревший default", "чужим default", `dev ` + st.Tunnels[0].WGInterface()} {
		if !strings.Contains(conf, want) {
			t.Errorf("в PreUp нет %q:\n%s", want, conf)
		}
	}
	if !strings.Contains(conf, "ip -4 route replace default dev %i table 300") {
		t.Error("нет default-маршрута в таблице метки")
	}
}

// Выходной узел туннеля обязан NAT'ить и подсети клиентов: иначе их пакеты
// уходят наружу с приватным адресом и ответ не возвращается. И принимать их
// по AllowedIPs — source-фильтр WireGuard отбросит чужие адреса.
func TestTunnelExitNatCoversClients(t *testing.T) {
	st := clientNetState()
	st.Nodes = append(st.Nodes, model.Node{ID: "exit", Name: "Выход", PublicAddr: "eu.example.com"})
	st.Tunnels = []model.Tunnel{{
		ID: "t1", Name: "eu", Kind: model.TunnelWG, Enabled: true,
		FromNode: "hub", ToNode: "exit", Subnet: "10.77.1.0/30", ListenPort: 51900,
		Mark: 300, ForwardPolicy: true,
		FromKeyPriv: zeroKey, FromKeyPub: zeroKey, ToKeyPriv: zeroKey, ToKeyPub: zeroKey,
	}}
	st.Inbounds[0].Egress = "tun:eu"
	st.Normalize()
	exit := st.Tunnels[0]
	conf, err := WGConfig(st, exit, "exit")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ip saddr { 10.88.0.200/32, 10.88.0.0/24 }",
		"AllowedIPs = 10.88.0.200/32, 10.88.0.0/24",
		"iptables -I FORWARD -i %i -j ACCEPT",
		"ip -4 route replace 10.88.0.0/24 dev %i",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("в конфиге выхода нет %q:\n%s", want, conf)
		}
	}
}
