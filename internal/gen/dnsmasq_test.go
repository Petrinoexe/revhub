package gen

import (
	"strings"
	"testing"

	"revhub/internal/model"
)

// dnsState — хаб с инфраструктурной сетью, пользовательским WG и зоной DNS.
func dnsState() model.State {
	st := model.Demo()
	st.Inbounds = append(st.Inbounds, model.Inbound{
		ID: "in-wg", NodeID: "hub", Tag: "wg", Kind: model.InboundWireGuard,
		Listen: "0.0.0.0", Port: 51820, Enabled: true, Egress: "tun:eu",
	})
	st.Clients[0].Inbounds = append(st.Clients[0].Inbounds, "in-wg")
	st.Infra = &model.InfraConfig{Enabled: true, NodeID: "hub"}
	st.InfraPeers = []model.InfraPeer{
		{Name: "srv-db", Address: "10.89.0.2/32", Enabled: true},
		{Name: "srv-app", Address: "10.89.0.3/32", Enabled: true},
		{Name: "off", Address: "10.89.0.4/32"},
	}
	st.DNS = &model.DNSConfig{Root: "infra.cringe"}
	st.Normalize()
	return st
}

func dnsSource(t *testing.T, st model.State) string {
	t.Helper()
	for _, tun := range st.Tunnels {
		if tun.Name == "eu" && tun.Enabled {
			from, _, err := tun.Addrs()
			if err != nil {
				t.Fatal(err)
			}
			return from
		}
	}
	t.Fatal("туннеля eu нет")
	return ""
}

func TestDNSMasqRendersZone(t *testing.T) {
	st := dnsState()
	files, ok, err := DNSMasq(st, "hub")
	if err != nil || !ok {
		t.Fatalf("зона не отрендерилась: ok=%v err=%v", ok, err)
	}
	src := dnsSource(t, st)
	for _, want := range []string{
		"port=53\n",
		"listen-address=10.89.0.1\n",
		"bind-dynamic\n",
		"no-hosts\n",
		"domain=infra.cringe\n",
		"local=/infra.cringe/\n",
		"no-resolv\n",
		"server=1.1.1.1@" + src + "\n",
		"server=1.0.0.1@" + src + "\n",
		"addn-hosts=/etc/dnsmasq.d/revhub/hosts\n",
	} {
		if !strings.Contains(files.Conf, want) {
			t.Errorf("в конфиге dnsmasq нет %q:\n%s", want, files.Conf)
		}
	}
	for _, want := range []string{
		"10.89.0.1\tpanel.infra.cringe\tpanel\n",
		"10.89.0.2\tsrv-db.infra.cringe\tsrv-db\n",
		"10.89.0.3\tsrv-app.infra.cringe\tsrv-app\n",
	} {
		if !strings.Contains(files.Hosts, want) {
			t.Errorf("в зоне нет %q:\n%s", want, files.Hosts)
		}
	}
	if strings.Contains(files.Hosts, "10.88.") || strings.Contains(files.Hosts, "off.") {
		t.Errorf("в зону попали клиентские адреса или выключенный пир:\n%s", files.Hosts)
	}
}

func TestDNSZoneWithoutClientInbound(t *testing.T) {
	st := model.Demo()
	st.Inbounds = nil
	st.Clients = nil
	st.Infra = &model.InfraConfig{Enabled: true, NodeID: "hub"}
	st.InfraPeers = []model.InfraPeer{{Name: "srv-db", Address: "10.89.0.2/32", Enabled: true}}
	st.DNS = &model.DNSConfig{Root: "infra.cringe", NodeID: "hub"}
	st.Normalize()
	files, ok, err := DNSMasq(st, "hub")
	if err != nil || !ok {
		t.Fatalf("зона должна создаваться без клиентских инбаундов: ok=%v err=%v", ok, err)
	}
	if !strings.Contains(files.Hosts, "srv-db.infra.cringe") {
		t.Fatalf("записи инфра-пира нет:\n%s", files.Hosts)
	}
}

func TestDNSMasqExplicitUpstream(t *testing.T) {
	st := dnsState()
	st.DNS.Upstream = []string{"9.9.9.9", "1.1.1.1:5353"}
	files, _, err := DNSMasq(st, "hub")
	if err != nil {
		t.Fatal(err)
	}
	src := dnsSource(t, st)
	for _, want := range []string{"no-resolv\n", "server=9.9.9.9@" + src + "\n", "server=1.1.1.1#5353@" + src + "\n"} {
		if !strings.Contains(files.Conf, want) {
			t.Errorf("нет %q:\n%s", want, files.Conf)
		}
	}
}

func TestDNSMasqOnlyOnItsNode(t *testing.T) {
	st := dnsState()
	if _, ok, _ := DNSMasq(st, "exit"); ok {
		t.Error("на узле без wg-infra зона рендериться не должна")
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
	for _, want := range []string{"/etc/dnsmasq.d/revhub.conf", "/etc/dnsmasq.d/revhub/hosts", "dnsmasq"} {
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
