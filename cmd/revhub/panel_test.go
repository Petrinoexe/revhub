package main

import (
	"strings"
	"testing"

	"revhub/internal/model"
)

func panelState() model.State {
	st := model.State{
		Version: model.StateVersion,
		Nodes:   []model.Node{{ID: "node-1", Name: "Этот узел", PublicAddr: "vpn.example.com:2096"}},
		Inbounds: []model.Inbound{
			{ID: "in-wg", NodeID: "node-1", Tag: "wg", Kind: model.InboundWireGuard,
				Listen: "0.0.0.0", Port: 51820, Enabled: true},
			{ID: "in-wg2", NodeID: "node-1", Tag: "wg-backup", Kind: model.InboundWireGuard,
				Listen: "0.0.0.0", Port: 51830, Enabled: true},
			{ID: "in-vless", NodeID: "node-1", Tag: "vless", Kind: "vless",
				Listen: "0.0.0.0", Port: 443, Security: "none", Enabled: true},
		},
		Clients: []model.Client{{Email: "a@b", Enabled: true, Inbounds: []string{"in-wg"}}},
		Panel:   &model.PanelConfig{Listen: "127.0.0.1:2096"},
	}
	st.Normalize()
	return st
}

func TestResolvePanelAddr(t *testing.T) {
	st := panelState()
	cases := []struct{ target, want string }{
		{"localhost", "127.0.0.1:2096"},
		{"LOOPBACK", "127.0.0.1:2096"},
		{"127.0.0.1", "127.0.0.1:2096"},
		{"wg", "10.88.0.1:2096"},
		{"wg:wg", "10.88.0.1:2096"},
		{"wg:wg-backup", "10.88.1.1:2096"},
		{"wg:wgc-wg-backup", "10.88.1.1:2096"}, // по имени интерфейса
		{"wg-backup", "10.88.1.1:2096"},        // голая метка инбаунда
		{"WGC-WG", "10.88.0.1:2096"},           // имя интерфейса без префикса
		{"10.88.0.1", "10.88.0.1:2096"},
		{"10.88.0.1:8443", "10.88.0.1:8443"},
		{"panel.example.com", "panel.example.com:2096"},
		{" panel.example.com:9000 ", "panel.example.com:9000"},
		{"internet", "0.0.0.0:2096"},
		{"public", "0.0.0.0:2096"},
		{"0.0.0.0", "0.0.0.0:2096"},
	}
	for _, c := range cases {
		got, err := resolvePanelAddr(st, "node-1", c.target, 2096)
		if err != nil {
			t.Errorf("%q: %v", c.target, err)
			continue
		}
		if got != c.want {
			t.Errorf("%q → %q, ожидалось %q", c.target, got, c.want)
		}
	}
}

func TestResolvePanelAddrKeepsPort(t *testing.T) {
	st := panelState()
	if got, err := resolvePanelAddr(st, "node-1", "wg", 2098); err != nil || got != "10.88.0.1:2098" {
		t.Fatalf("порт из текущего адреса не сохранился: %q, %v", got, err)
	}
}

func TestResolvePanelAddrErrors(t *testing.T) {
	st := panelState()
	for _, target := range []string{"", "wg:nope", "10.88.0.1:abc"} {
		if got, err := resolvePanelAddr(st, "node-1", target, 2096); err == nil {
			t.Errorf("%q: ожидалась ошибка, получено %q", target, got)
		}
	}
	// узел без WireGuard-инбаунда: переключаться некуда
	if _, err := resolvePanelAddr(st, "node-1", "wg:nope", 2096); err == nil ||
		!strings.Contains(err.Error(), "wg, wg-backup") {
		t.Errorf("в ошибке нет списка доступных инбаундов: %v", err)
	}
	empty := panelState()
	empty.Inbounds = nil
	empty.Normalize()
	if _, err := resolvePanelAddr(empty, "node-1", "wg", 2096); err == nil {
		t.Error("без WireGuard-инбаундов wg не должен разрешаться")
	}
}

// expose ставится по адресу: петля и WG — нет, всё остальное — да.
func TestPanelExposeFor(t *testing.T) {
	st := panelState()
	cases := map[string]bool{
		"127.0.0.1:2096":        false,
		"10.88.0.1:2096":        false,
		"10.88.1.1:2096":        false,
		"0.0.0.0:2096":          true,
		"203.0.113.7:2096":      true,
		"panel.example.com:443": true,
	}
	for addr, want := range cases {
		if got := panelExposeFor(st, "node-1", addr); got != want {
			t.Errorf("%s: expose=%v, ожидалось %v", addr, got, want)
		}
	}
}

func TestPanelChoices(t *testing.T) {
	st := panelState()
	choices := panelChoices(st, "node-1")
	if len(choices) != 4 { // loopback + интернет + два WG-инбаунда
		t.Fatalf("ожидалось 3 варианта, получено %d: %+v", len(choices), choices)
	}
	byAddr := map[string]panelChoice{}
	for _, c := range choices {
		byAddr[c.addr] = c
	}
	if _, ok := byAddr["127.0.0.1:2096"]; !ok {
		t.Error("loopback потерялся")
	}
	if c, ok := byAddr["10.88.1.1:2096"]; !ok || !strings.Contains(c.label, "wg-backup") {
		t.Errorf("вариант второго инбаунда неверный: %+v", c)
	}
	// чужой узел: только loopback
	if got := panelChoices(st, "other"); len(got) != 2 {
		t.Errorf("для чужого узла ожидался только loopback: %+v", got)
	}
}
