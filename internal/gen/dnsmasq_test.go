package gen

import (
	"strings"
	"testing"

	"revhub/internal/model"
)

// dnsState — хаб с клиентской сетью WireGuard и включённой зоной DNS.
func dnsState() model.State {
	st := model.State{
		Version: model.StateVersion,
		Nodes: []model.Node{
			{ID: "hub", Name: "Хаб", PublicAddr: "vpn.example.com:2096"},
			{ID: "exit", Name: "Выход", PublicAddr: "eu.example.com"},
		},
		Inbounds: []model.Inbound{{
			ID: "in-wg", NodeID: "hub", Tag: "wg", Kind: model.InboundWireGuard,
			Listen: "0.0.0.0", Port: 51820, Enabled: true,
		}},
		Clients: []model.Client{
			{Email: "alice@revhub", Enabled: true, Inbounds: []string{"in-wg"}},
			{Email: "bob@revhub", Enabled: true, Inbounds: []string{"in-wg"}},
			{Email: "carol@revhub", Inbounds: []string{"in-wg"}}, // выключен
		},
		DNS: &model.DNSConfig{Root: "vpn.internal"},
	}
	st.Normalize()
	// Зона DNS существует только при ядерном клиентском интерфейсе.
	st.Inbounds[0].WireGuard.Kernel = true
	return st
}

func TestDNSMasqRendersZone(t *testing.T) {
	st := dnsState()
	files, ok, err := DNSMasq(st, "hub")
	if err != nil || !ok {
		t.Fatalf("зона не отрендерилась: ok=%v err=%v", ok, err)
	}
	for _, want := range []string{
		"port=53\n",
		"listen-address=10.88.0.1\n",
		"bind-dynamic\n",
		"no-hosts\n",
		"domain=vpn.internal\n",
		"local=/vpn.internal/\n",
		"addn-hosts=/etc/revhub/dns-hosts\n",
	} {
		if !strings.Contains(files.Conf, want) {
			t.Errorf("в конфиге dnsmasq нет %q:\n%s", want, files.Conf)
		}
	}
	if strings.Contains(files.Conf, "no-resolv") {
		t.Error("без явных upstream'ов dnsmasq должен читать resolv.conf узла")
	}
	alice := st.Clients[0]
	addr := alice.WireGuard["in-wg"].Address
	if addr == "" {
		t.Fatal("у клиента нет адреса WireGuard")
	}
	ip := strings.TrimSuffix(addr, "/32")
	for _, want := range []string{
		ip + "\talice.vpn.internal\talice\n",
		"10.88.0.1\tpanel.vpn.internal\tpanel\n",
	} {
		if !strings.Contains(files.Hosts, want) {
			t.Errorf("в зоне нет %q:\n%s", want, files.Hosts)
		}
	}
	if strings.Contains(files.Hosts, "carol") {
		t.Error("выключенный клиент попал в зону")
	}
}

func TestDNSMasqExplicitUpstream(t *testing.T) {
	st := dnsState()
	st.DNS.Upstream = []string{"9.9.9.9", "1.1.1.1:5353"}
	files, _, err := DNSMasq(st, "hub")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"no-resolv\n", "server=9.9.9.9\n", "server=1.1.1.1#5353\n"} {
		if !strings.Contains(files.Conf, want) {
			t.Errorf("нет %q:\n%s", want, files.Conf)
		}
	}
}

func TestDNSMasqOnlyOnItsNode(t *testing.T) {
	st := dnsState()
	if _, ok, _ := DNSMasq(st, "exit"); ok {
		t.Error("на узле без WireGuard-инбаунда зона рендериться не должна")
	}
	st.DNS.Root = ""
	if _, ok, _ := DNSMasq(st, "hub"); ok {
		t.Error("без зоны конфиг dnsmasq не нужен")
	}
}

// apply.sh должен привезти оба файла и перезапустить резолвер, иначе зона
// окажется только в каталоге артефактов.
func TestDNSArtifactsReachApplyScript(t *testing.T) {
	st := dnsState()
	files, err := Artifacts(st, "hub")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]File{}
	for _, f := range files {
		names[f.Name] = f
	}
	for _, want := range []string{DNSMasqConfName, DNSHostsFileName} {
		if _, ok := names[want]; !ok {
			t.Fatalf("артефакта %s нет в наборе", want)
		}
	}
	script := names["apply.sh"].Content
	for _, want := range []string{"/etc/dnsmasq.d/revhub.conf", "/etc/revhub/dns-hosts", "dnsmasq"} {
		if !strings.Contains(script, want) {
			t.Errorf("apply.sh не ставит %q", want)
		}
	}
}

// Открытая наружу панель должна попасть в порты узла: apply открывает их в
// ufw/firewalld, иначе снаружи просто ничего не отвечает.
func TestNodePortsIncludeExposedPanel(t *testing.T) {
	st := dnsState()
	st.Panel = &model.PanelConfig{Listen: "0.0.0.0:2096", NodeID: "hub", Expose: true}
	if got := NodePorts(st, "hub"); !contains(got, "2096/tcp") {
		t.Errorf("порт панели не попал в список: %v", got)
	}
	if got := NodePorts(st, "exit"); contains(got, "2096/tcp") {
		t.Errorf("на чужом узле порт панели не нужен: %v", got)
	}
	st.Panel = &model.PanelConfig{Listen: "10.88.0.1:2096", NodeID: "hub"}
	if got := NodePorts(st, "hub"); contains(got, "2096/tcp") {
		t.Errorf("панель внутри WG не требует открытого порта: %v", got)
	}
}

func TestDNSMasqBadZone(t *testing.T) {
	st := dnsState()
	st.DNS.Root = "not a zone"
	if _, _, err := DNSMasq(st, "hub"); err == nil {
		t.Fatal("зона с пробелом должна ломать валидацию до рендера")
	}
}
