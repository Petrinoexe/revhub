package sub

import (
	"encoding/json"
	"strings"
	"testing"

	"revhub/internal/model"
)

func TestSingBoxJSONRendersThroneConfig(t *testing.T) {
	st := wgState()
	st.DNS = &model.DNSConfig{Root: "vpn.internal", NodeID: "hub"}
	raw, ok, err := SingBoxJSON(st, st.Clients[0])
	if err != nil || !ok {
		t.Fatalf("конфиг не отрендерился: ok=%v err=%v", ok, err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("конфиг не JSON: %v", err)
	}

	// outbound
	obs := cfg["outbounds"].([]any)
	wg := obs[0].(map[string]any)
	peer := st.Clients[0].WireGuard["in-wg"]
	for k, want := range map[string]any{
		"type":            "wireguard",
		"server":          "hub.example.com",
		"server_port":     float64(51820),
		"private_key":     peer.PrivateKey,
		"peer_public_key": st.Inbounds[0].WireGuard.PublicKey,
		"pre_shared_key":  peer.PresharedKey,
	} {
		if wg[k] != want {
			t.Errorf("outbound[%s] = %v, ожидалось %v", k, wg[k], want)
		}
	}
	if got := wg["local_address"].([]any)[0]; got != peer.Address {
		t.Errorf("local_address = %v, ожидалось %v", got, peer.Address)
	}

	// DNS: внутренняя зона идёт на dnsmasq хаба, остальное — наружу через туннель
	dns := cfg["dns"].(map[string]any)
	servers := dns["servers"].([]any)
	infra := servers[0].(map[string]any)
	if infra["server"] != "10.88.0.1" || infra["detour"] != "wg-out" {
		t.Errorf("infra DNS = %v", infra)
	}
	rules := dns["rules"].([]any)
	rule := rules[0].(map[string]any)
	if rule["server"] != "infra" || rule["domain_suffix"].([]any)[0] != ".vpn.internal" {
		t.Errorf("правило зоны = %v", rule)
	}

	// весь трафик через туннель
	route := cfg["route"].(map[string]any)
	if route["final"] != "wg-out" || route["auto_detect_interface"] != true {
		t.Errorf("route = %v", route)
	}
}

func TestSingBoxJSONWithoutZoneHasNoRules(t *testing.T) {
	st := wgState() // DNS-зона выключена
	raw, ok, err := SingBoxJSON(st, st.Clients[0])
	if err != nil || !ok {
		t.Fatalf("конфиг не отрендерился: ok=%v err=%v", ok, err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	dns := cfg["dns"].(map[string]any)
	if _, exists := dns["rules"]; exists {
		t.Error("без зоны rules не нужен: sing-box ругается на null")
	}
	if servers := dns["servers"].([]any); len(servers) != 1 || servers[0].(map[string]any)["tag"] != "default" {
		t.Errorf("без зоны должен остаться только внешний DNS: %v", servers)
	}
}

func TestSingBoxJSONSkipsInactive(t *testing.T) {
	st := wgState()
	st.Clients[0].ExpiresAt = "2000-01-01T00:00:00Z"
	if _, ok, _ := SingBoxJSON(st, st.Clients[0]); ok {
		t.Error("истёкший клиент не должен получать конфиг")
	}
	st.Clients[0].ExpiresAt = ""
	st.Clients[0].Enabled = false
	if _, ok, _ := SingBoxJSON(st, st.Clients[0]); ok {
		t.Error("выключенный клиент не должен получать конфиг")
	}
}

func TestSingBoxJSONCoheresWithWireGuardLink(t *testing.T) {
	st := wgState()
	raw, ok, _ := SingBoxJSON(st, st.Clients[0])
	if !ok {
		t.Fatal("нет конфига")
	}
	// Те же ключи, что в wireguard:// ссылке — иначе два формата одной
	// подписки раздадут разные учётные данные.
	peer := st.Clients[0].WireGuard["in-wg"]
	for _, s := range []string{peer.PrivateKey, peer.PresharedKey, st.Inbounds[0].WireGuard.PublicKey} {
		if !strings.Contains(string(raw), s) {
			t.Errorf("в конфиге нет ключа %q…", s[:8])
		}
	}
}
