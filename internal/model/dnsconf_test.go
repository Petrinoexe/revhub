package model

import (
	"strings"
	"testing"
)

func dnsTestState() State {
	st := State{
		Version: StateVersion,
		Nodes:   []Node{{ID: "hub", Name: "Хаб", PublicAddr: "vpn.example.com:2096"}},
		Inbounds: []Inbound{{
			ID: "in-wg", NodeID: "hub", Tag: "wg", Kind: InboundWireGuard,
			Listen: "0.0.0.0", Port: 51820, Enabled: true,
		}},
		Clients: []Client{
			{Email: "alice@revhub", Enabled: true, Inbounds: []string{"in-wg"}},
			{Email: "alice@other.example", Enabled: true, Inbounds: []string{"in-wg"}},
			{Email: "Иван Петров", Enabled: true, Inbounds: []string{"in-wg"}},
		},
		DNS: &DNSConfig{Root: "vpn.internal"},
	}
	st.Normalize()
	return st
}

// Две почты с одинаковым началом не должны получить одно имя в зоне.
func TestHostnamesAreUnique(t *testing.T) {
	st := dnsTestState()
	got := []string{}
	for _, c := range st.Clients {
		got = append(got, c.Hostname)
	}
	if got[0] != "alice" || got[1] != "alice-2" {
		t.Errorf("имена клиентов = %v, ожидалось alice и alice-2", got)
	}
	if got[2] == "" || !validLabel(got[2]) {
		t.Errorf("имя без латиницы должно замениться на метку, получено %q", got[2])
	}
}

func TestDNSRecords(t *testing.T) {
	st := dnsTestState()
	recs := DNSRecords(st, "hub")
	byName := map[string]DNSRecord{}
	for _, r := range recs {
		byName[r.Name] = r
	}
	if panel, ok := byName["panel.vpn.internal"]; !ok || panel.IP != "10.88.0.1" || panel.Kind != "panel" {
		t.Fatalf("записи панели нет: %+v", recs)
	}
	alice, ok := byName["alice.vpn.internal"]
	if !ok || alice.IP != "10.88.0.2" || alice.Kind != "client" {
		t.Fatalf("записи клиента нет: %+v", recs)
	}
	if _, ok := byName["alice-2.vpn.internal"]; !ok {
		t.Error("второй alice потерялся")
	}
	if recs := DNSRecords(st, "exit"); len(recs) != 0 {
		t.Errorf("на чужом узле записей быть не должно: %+v", recs)
	}
}

func TestDNSValidation(t *testing.T) {
	st := dnsTestState()
	if err := st.Validate(); err != nil {
		t.Fatalf("состояние с зоной должно быть валидным: %v", err)
	}
	st.DNS.Root = "vpn..internal"
	if err := st.Validate(); err == nil || !strings.Contains(err.Error(), "DNS") {
		t.Fatalf("кривая зона не поймана: %v", err)
	}
	st.DNS.Root = "vpn.internal"
	st.DNS.Upstream = []string{"dns.example.com"}
	if err := st.Validate(); err == nil || !strings.Contains(err.Error(), "upstream") {
		t.Fatalf("upstream-имя вместо IP не поймано: %v", err)
	}
	st.DNS.Upstream = []string{"9.9.9.9:5353"}
	if err := st.Validate(); err != nil {
		t.Errorf("IP:порт должен приниматься: %v", err)
	}
	st.DNS.NodeID = "exit"
	if err := st.Validate(); err == nil {
		t.Error("DNS на узле без WireGuard должен ломать валидацию")
	}
	st.DNS.NodeID = "hub"
	st.Clients[0].Hostname = "Bob"
	if err := st.Validate(); err == nil || !strings.Contains(err.Error(), "имя") {
		t.Errorf("имя с заглавными не поймано: %v", err)
	}
}

func TestPanelListen(t *testing.T) {
	st := dnsTestState()
	if got := st.Panel.Addr(); got != DefaultPanelListen {
		t.Errorf("адрес панели по умолчанию = %q", got)
	}
	if !st.Panel.LoopbackOnly() {
		t.Error("по умолчанию панель должна быть только на loopback")
	}
	st.Panel.Listen = "10.88.0.1:2096"
	if err := st.Validate(); err != nil {
		t.Errorf("адрес WG-интерфейса должен приниматься: %v", err)
	}
	if st.Panel.LoopbackOnly() {
		t.Error("адрес WG-интерфейса — уже не loopback")
	}
	st.Panel.Listen = "192.168.1.5:2096"
	if err := st.Validate(); err == nil || !strings.Contains(err.Error(), "WireGuard") {
		t.Errorf("чужой адрес не поймано: %v", err)
	}
}

// expose — осознанный флаг: без него 0.0.0.0 и публичный адрес запрещены,
// с ним панель открывается наружу.
func TestPanelExpose(t *testing.T) {
	st := dnsTestState()
	st.Panel = &PanelConfig{Listen: "0.0.0.0:2096", NodeID: "hub"}
	st.Normalize()
	if err := st.Validate(); err == nil || !strings.Contains(err.Error(), "expose") {
		t.Fatalf("0.0.0.0 без expose должен ломать валидацию: %v", err)
	}
	st.Panel.Expose = true
	if err := st.Validate(); err != nil {
		t.Fatalf("0.0.0.0 с expose должен приниматься: %v", err)
	}
	st.Panel.Expose = false
	st.Panel.Listen = "203.0.113.7:2096"
	if err := st.Validate(); err == nil {
		t.Fatal("публичный адрес без expose должен ломать валидацию")
	}
	st.Panel.Expose = true
	if err := st.Validate(); err != nil {
		t.Fatalf("публичный адрес с expose должен приниматься: %v", err)
	}
	st.Panel.Listen = "127.0.0.1:2096"
	if err := st.Validate(); err == nil {
		t.Fatal("expose с петлёй — противоречие, должно ломаться")
	}
	st.Panel.Expose = false
	st.Panel.Listen = "10.88.0.1:2096"
	if err := st.Validate(); err != nil {
		t.Fatalf("адрес WG без expose должен приниматься: %v", err)
	}
	st.Panel.Expose = true
	if err := st.Validate(); err == nil || !strings.Contains(err.Error(), "expose") {
		t.Fatalf("expose на адресе WG — лишний флаг, должно ломаться: %v", err)
	}
	if got := (&PanelConfig{Listen: "0.0.0.0:8443"}).Port(); got != 8443 {
		t.Errorf("Port() = %d", got)
	}
}

func TestAssignWireGuardSubnets(t *testing.T) {
	st := State{
		Nodes: []Node{{ID: "hub", PublicAddr: "vpn.example.com"}},
		Inbounds: []Inbound{
			{ID: "a", NodeID: "hub", Tag: "wg1", Kind: InboundWireGuard, Listen: "0.0.0.0", Port: 51820, Enabled: true},
			{ID: "b", NodeID: "hub", Tag: "wg2", Kind: InboundWireGuard, Listen: "0.0.0.0", Port: 51830, Enabled: true},
		},
		Clients: []Client{{Email: "a@b", Enabled: true, Inbounds: []string{"a", "b"}}},
	}
	st.Normalize()
	if st.Inbounds[0].WireGuard.Subnet == st.Inbounds[1].WireGuard.Subnet {
		t.Fatalf("инбаундам выдали одну подсеть: %s", st.Inbounds[0].WireGuard.Subnet)
	}
	if st.Inbounds[0].WireGuard.Subnet != "10.88.0.0/24" || st.Inbounds[1].WireGuard.Subnet != "10.88.1.0/24" {
		t.Errorf("подсети = %s и %s", st.Inbounds[0].WireGuard.Subnet, st.Inbounds[1].WireGuard.Subnet)
	}
	if err := st.Validate(); err != nil {
		t.Errorf("автоподбор подсетей должен давать валидное состояние: %v", err)
	}
	// вручную заданная такая же подсеть — уже ошибка
	st.Inbounds[1].WireGuard.Subnet = "10.88.0.0/24"
	if err := st.Validate(); err == nil || !strings.Contains(err.Error(), "пересекается") {
		t.Errorf("пересечение подсетей не поймано: %v", err)
	}
}

func TestWireGuardEgress(t *testing.T) {
	st := Demo()
	st.Inbounds = append(st.Inbounds, Inbound{
		ID: "in-wg", NodeID: "hub", Tag: "wg", Kind: InboundWireGuard,
		Listen: "0.0.0.0", Port: 51830, Enabled: true, Egress: "tun:eu",
	})
	st.Clients[0].Inbounds = append(st.Clients[0].Inbounds, "in-wg")
	st.Normalize()
	if err := st.Validate(); err != nil {
		t.Fatalf("выход в существующий туннель должен быть валиден: %v", err)
	}
	st.Inbounds[1].Egress = "tun:nope"
	if err := st.Validate(); err == nil || !strings.Contains(err.Error(), "выход") {
		t.Errorf("несуществующий туннель в выходе не пойман: %v", err)
	}
}
