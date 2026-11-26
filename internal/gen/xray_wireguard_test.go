package gen

import (
	"encoding/json"
	"strings"
	"testing"

	"revhub/internal/model"
)

func wireguardUserState() model.State {
	st := model.Demo()
	st.Inbounds = append(st.Inbounds, model.Inbound{
		ID: "in-wg", NodeID: "hub", Tag: "wg", Kind: model.InboundWireGuard,
		Listen: "0.0.0.0", Port: 51820, Enabled: true,
	})
	st.Clients[0].Inbounds = append(st.Clients[0].Inbounds, "in-wg")
	st.Normalize()
	return st
}

// Пользовательский WireGuard — userspace-inbound Xray по формату 3x-ui:
// secretKey + peers(publicKey/preSharedKey/allowedIPs/email) + mtu, без address.
func TestXrayWireGuardInboundMatches3xUI(t *testing.T) {
	st := wireguardUserState()
	raw, err := XrayJSON(st, "hub")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	var inbound map[string]any
	for _, i := range cfg["inbounds"].([]any) {
		m := i.(map[string]any)
		if m["tag"] == "wg" {
			inbound = m
		}
	}
	if inbound == nil {
		t.Fatal("WireGuard-инбаунд не попал в xray.json")
	}
	in := st.Inbounds[len(st.Inbounds)-1]
	if inbound["protocol"] != "wireguard" || int(inbound["port"].(float64)) != in.Port {
		t.Errorf("шапка инбаунда: %v", inbound)
	}
	settings := inbound["settings"].(map[string]any)
	if settings["secretKey"] != in.WireGuard.PrivateKey {
		t.Error("secretKey не совпадает с приватным ключом сервера")
	}
	if _, exists := settings["address"]; exists {
		t.Error("у inbound-а Xray нет address; клиентские адреса задаются allowedIPs")
	}
	if settings["mtu"].(float64) != 1420 {
		t.Errorf("mtu = %v", settings["mtu"])
	}
	peers := settings["peers"].([]any)
	if len(peers) != 1 {
		t.Fatalf("ожидался 1 пир, получено %v", peers)
	}
	peer := peers[0].(map[string]any)
	want := st.Clients[0].WireGuard["in-wg"]
	for k, v := range map[string]any{
		"publicKey":    want.PublicKey,
		"preSharedKey": want.PresharedKey,
		"email":        st.Clients[0].Email,
	} {
		if peer[k] != v {
			t.Errorf("peer[%s] = %v, ожидалось %v", k, peer[k], v)
		}
	}
	ips := peer["allowedIPs"].([]any)
	if len(ips) != 1 || ips[0] != want.Address {
		t.Errorf("allowedIPs = %v, ожидалось %v", ips, want.Address)
	}
}

// Ядерный wg-quick конфиг клиентов больше не рендерится: остались только
// туннели и инфраструктура.
func TestNoKernelClientWGArtifacts(t *testing.T) {
	st := wireguardUserState()
	files, err := Artifacts(st, "hub")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasPrefix(f.Name, "wgc-") {
			t.Fatalf("клиентский wg-конфиг всё ещё генерируется: %s", f.Name)
		}
	}
	// а xray-инбаунд на месте
	byName := map[string]string{}
	for _, f := range files {
		byName[f.Name] = f.Content
	}
	if !strings.Contains(byName["xray.json"], `"protocol": "wireguard"`) {
		t.Error("в xray.json нет userspace WireGuard-инбаунда")
	}
}

// Без ядерного клиентского интерфейса зона dnsmasq не рендерится (DNS — этап 7).
func TestNoDNSWithoutKernelInterface(t *testing.T) {
	st := wireguardUserState()
	st.DNS = &model.DNSConfig{Root: "vpn.internal", NodeID: "hub"}
	files, err := Artifacts(st, "hub")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f.Name == "dnsmasq-revhub.conf" {
			t.Fatal("dnsmasq-зона не должна рендериться без ядерного wgc-интерфейса")
		}
	}
}

// Выход клиентской сети живёт в inbound.egress и рендерится системным
// правилом по inboundTag выше пользовательских маршрутов.
func TestInboundEgressRuleByTag(t *testing.T) {
	st := wireguardUserState()
	in := &st.Inbounds[len(st.Inbounds)-1]
	in.Egress = "tun:eu"
	rules := rulesOf(t, st, "hub")
	wantTag := in.Tag
	seen := -1
	catch := -1
	for i, r := range rules {
		m := r.(map[string]any)
		if tags, ok := m["inboundTag"].([]any); ok && len(tags) == 1 && tags[0] == wantTag && m["outboundTag"] == "tun:eu" {
			seen = i
		}
		if m["outboundTag"] == "direct" {
			if _, ok := m["network"]; ok {
				catch = i
			}
		}
	}
	if seen < 0 {
		t.Fatalf("нет правила inboundTag=%s → tun:eu: %v", wantTag, rules)
	}
	if catch >= 0 && seen > catch {
		t.Fatal("выход сети должен стоять выше direct-заглушки")
	}
}

// Личный выход клиента (source) важнее выхода всей сети.
func TestClientEgressBeatsInboundEgress(t *testing.T) {
	st := wireguardUserState()
	in := &st.Inbounds[len(st.Inbounds)-1]
	in.Egress = "tun:eu"
	st.Clients[0].Egress = model.TagDirect
	rules := rulesOf(t, st, "hub")
	src, inb := -1, -1
	for i, r := range rules {
		m := r.(map[string]any)
		if _, ok := m["source"]; ok && m["outboundTag"] == model.TagDirect {
			src = i
		}
		if _, ok := m["inboundTag"]; ok && m["outboundTag"] == "tun:eu" {
			inb = i
		}
	}
	if src < 0 || inb < 0 {
		t.Fatalf("правила не найдены: source=%d inbound=%d %v", src, inb, rules)
	}
	if src > inb {
		t.Fatal("личный выход клиента должен стоять выше выхода сети")
	}
}

func TestClientEgressRuleBySource(t *testing.T) {
	st := wireguardUserState()
	st.Clients[0].Egress = "tun:eu"
	rules := rulesOf(t, st, "hub")
	addr := st.Clients[0].WireGuard["in-wg"].Address
	found := false
	for _, r := range rules {
		m := r.(map[string]any)
		if m["outboundTag"] != "tun:eu" {
			continue
		}
		if src, ok := m["source"].([]any); ok && len(src) == 1 && src[0] == addr {
			found = true
		}
	}
	if !found {
		t.Fatalf("нет правила source=%s → tun:eu: %v", addr, rules)
	}
}
