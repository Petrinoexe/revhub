package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"revhub/internal/model"
	"revhub/internal/store"
)

// Порт, занятый туннелем на том же узле, не должен мешать создать инбаунд:
// он сдвигается на свободный, а состояние остаётся валидным.
func TestWireGuardPortMovesOffTunnelPort(t *testing.T) {
	st := model.Demo()
	for _, tunnel := range st.Tunnels {
		if !tunnel.Enabled || (tunnel.Kind != model.TunnelWG && tunnel.Kind != model.TunnelWGReverse) {
			continue
		}
		st.Inbounds = append(st.Inbounds, model.Inbound{
			ID: "in-wg", Tag: "wg", Kind: model.InboundWireGuard, Enabled: true,
			NodeID: tunnel.ListenerNode(), Port: tunnel.ListenPort,
		})
		st.Normalize()
		if err := st.Validate(); err != nil {
			t.Fatalf("инбаунд должен создаваться: %v", err)
		}
		if got := st.Inbounds[len(st.Inbounds)-1].Port; got == tunnel.ListenPort {
			t.Fatalf("порт остался занятым туннелем (%d)", got)
		}
		return
	}
	t.Fatal("test requires an enabled WireGuard tunnel")
}

func TestWireGuardClientSubscription(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	handler := (&Server{Store: db, NoAuth: true, OutDir: outDir}).Handler()
	request := func(method, path string, body []byte) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(method, path, bytes.NewReader(body)))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", method, w.Code, w.Body.String())
		}
		return w
	}
	draft := model.State{
		Nodes: []model.Node{{ID: "hub", PublicAddr: "hub.example.com:2096"}},
		Inbounds: []model.Inbound{
			{ID: "in-vless", NodeID: "hub", Tag: "vless", Kind: "vless", Port: 443, Security: "none", Enabled: true},
			{ID: "in-wg", NodeID: "hub", Tag: "wg", Kind: "wireguard", Port: 51820, Enabled: true},
		},
		Clients: []model.Client{
			{Email: "alice", Enabled: true, Inbounds: []string{"in-vless", "in-wg"}},
			{Email: "disabled", Inbounds: []string{"in-wg"}},
			{Email: "expired", Enabled: true, ExpiresAt: "2000-01-01T00:00:00Z", Inbounds: []string{"in-wg"}},
		},
	}
	body, err := json.Marshal(draft)
	if err != nil {
		t.Fatal(err)
	}
	saved := request(http.MethodPut, "/api/state", body)
	st := db.Snapshot()
	c := st.Clients[0]
	if c.ID == "" || c.UUID == "" || c.SubToken == "" {
		t.Fatal("client credentials were not generated")
	}
	readSubscription := func() string {
		t.Helper()
		w := request(http.MethodGet, "/sub/"+c.SubToken, nil)
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("subscription contains private keys and must not be cached")
		}
		raw, err := base64.StdEncoding.DecodeString(w.Body.String())
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	contents := readSubscription()
	lines := strings.Split(contents, "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "vless://") {
		t.Fatal("expected VLESS and WireGuard in the same subscription")
	}
	wg, err := url.Parse(lines[1])
	if err != nil {
		t.Fatal("invalid WireGuard URI")
	}
	if wg.Scheme != "wireguard" || wg.Host != "hub.example.com:51820" || wg.User == nil {
		t.Fatal("incorrect WireGuard endpoint or credentials")
	}
	for _, value := range []string{wg.User.Username(), wg.Query().Get("publickey"), wg.Query().Get("presharedkey")} {
		if k, err := base64.StdEncoding.DecodeString(value); err != nil || len(k) != 32 {
			t.Fatal("missing or invalid WireGuard key")
		}
	}
	if wg.Query().Get("address") != "10.88.0.2/32" {
		t.Fatal("missing client address")
	}
	peer := c.WireGuard["in-wg"]
	if wg.User.Username() != peer.PrivateKey || wg.Query().Get("presharedkey") != peer.PresharedKey || wg.Query().Get("publickey") != st.Inbounds[1].WireGuard.PublicKey {
		t.Fatal("subscription does not match the saved credentials")
	}
	// Клиентский WireGuard теперь userspace-inbound Xray: в превью обязан быть
	// protocol=wireguard с публичным ключом клиента, но никогда — приватным.
	preview := request(http.MethodGet, "/api/preview?node=hub", nil)
	if !bytes.Contains(preview.Body.Bytes(), []byte(`"protocol": "wireguard"`)) ||
		!bytes.Contains(preview.Body.Bytes(), []byte(peer.PublicKey)) {
		t.Fatal("WireGuard inbound must be rendered into xray.json")
	}
	if bytes.Contains(preview.Body.Bytes(), []byte(peer.PrivateKey)) {
		t.Fatal("private key must not appear in server config")
	}
	for _, inactive := range st.Clients[1:] {
		other := inactive.WireGuard["in-wg"]
		if other.Address == "" || other.Address == peer.Address || other.PublicKey == peer.PublicKey {
			t.Fatal("clients must have separate WireGuard credentials and addresses")
		}
		if bytes.Contains(preview.Body.Bytes(), []byte(other.PublicKey)) ||
			request(http.MethodGet, "/sub/"+inactive.SubToken, nil).Body.Len() != 0 {
			t.Fatal("inactive WireGuard client was included in the config or subscription")
		}
	}
	request(http.MethodPut, "/api/state", saved.Body.Bytes())
	reopened, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	handler = (&Server{Store: reopened, NoAuth: true}).Handler()
	if readSubscription() != contents {
		t.Fatal("saving/reopening rotated existing credentials")
	}
}

// Подписка — единственный способ выдать клиенту WireGuard: .conf больше не
// генерируется, сервер работает userspace-inbound'ом Xray. Параметры ссылки
// должны совпадать с форматом 3x-ui/v2rayN, иначе Throne не соберёт outbound.
func TestWireGuardSubscriptionCarriesXrayParams(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	handler := (&Server{Store: db, NoAuth: true}).Handler()
	draft := model.State{
		Nodes: []model.Node{{ID: "hub", PublicAddr: "hub.example.com:2096"}},
		Inbounds: []model.Inbound{
			{ID: "in-wg", NodeID: "hub", Tag: "wg", Kind: "wireguard", Port: 51820, Enabled: true},
		},
		Clients: []model.Client{{Email: "alice", Enabled: true, Inbounds: []string{"in-wg"}}},
	}
	body, _ := json.Marshal(draft)
	put := httptest.NewRecorder()
	handler.ServeHTTP(put, httptest.NewRequest(http.MethodPut, "/api/state", bytes.NewReader(body)))
	if put.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", put.Code, put.Body.String())
	}
	st := db.Snapshot()
	c := st.Clients[0]
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/sub/"+c.SubToken, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("подписка: %d", w.Code)
	}
	raw, err := base64.StdEncoding.DecodeString(w.Body.String())
	if err != nil {
		t.Fatalf("payload не base64: %v", err)
	}
	link := strings.TrimSpace(string(raw))
	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("ссылка не парсится: %v\n%s", err, link)
	}
	if u.Scheme != "wireguard" || u.User.Username() != c.WireGuard["in-wg"].PrivateKey {
		t.Fatalf("private key должен быть userinfo: %s", link)
	}
	q := u.Query()
	peer := c.WireGuard["in-wg"]
	for k, want := range map[string]string{
		"publickey":    st.Inbounds[0].WireGuard.PublicKey,
		"presharedkey": peer.PresharedKey,
		"address":      peer.Address,
		"mtu":          "1420",
		"keepalive":    "25",
	} {
		if got := q.Get(k); got != want {
			t.Errorf("%s = %q, ожидалось %q", k, got, want)
		}
	}
	if dns := q.Get("dns"); strings.Contains(dns, ",") {
		t.Errorf("dns должен быть одним адресом, получено %q", dns)
	}
	if u.Host != "hub.example.com:51820" {
		t.Errorf("endpoint = %q", u.Host)
	}
}
