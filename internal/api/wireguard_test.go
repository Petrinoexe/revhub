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

func TestWireGuardRejectsConflictingTunnelPort(t *testing.T) {
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
		if err := st.Validate(); err == nil || !strings.Contains(err.Error(), "UDP-порт") {
			t.Fatalf("expected a UDP port conflict, got %v", err)
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
	handler := (&Server{Store: db, NoAuth: true}).Handler()
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
	preview := request(http.MethodGet, "/api/preview?node=hub", nil)
	if !bytes.Contains(preview.Body.Bytes(), []byte(`"protocol": "wireguard"`)) || bytes.Contains(preview.Body.Bytes(), []byte(peer.PrivateKey)) {
		t.Fatal("incorrect WireGuard server config")
	}
	if !bytes.Contains(preview.Body.Bytes(), []byte(peer.PublicKey)) {
		t.Fatal("active WireGuard peer was not rendered")
	}
	for _, inactive := range st.Clients[1:] {
		other := inactive.WireGuard["in-wg"]
		if other.Address == "" || other.Address == peer.Address || other.PublicKey == peer.PublicKey {
			t.Fatal("clients must have separate WireGuard credentials and addresses")
		}
		if bytes.Contains(preview.Body.Bytes(), []byte(other.PublicKey)) || request(http.MethodGet, "/sub/"+inactive.SubToken, nil).Body.Len() != 0 {
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
