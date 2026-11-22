package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"revhub/internal/certs"
	"revhub/internal/model"
	"revhub/internal/store"
)

func TestPanelTLSInbound(t *testing.T) {
	dir := t.TempDir()
	pair, err := certs.SelfSigned(certs.Options{Hosts: []string{"hub.example.test"}, Days: 2, Prefix: filepath.Join(dir, "panel")})
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	handler := (&Server{Store: db, NoAuth: true, LocalNode: "hub", TLSCert: pair.CertFile, TLSKey: pair.KeyFile}).Handler()
	draft := model.State{Nodes: []model.Node{{ID: "hub", PublicAddr: "hub.example.test:2096"}, {ID: "exit", PublicAddr: "exit.example.test"}}, Inbounds: []model.Inbound{{ID: "in", Tag: "entry", NodeID: "hub", Kind: "vless", Port: 443, Security: "tls", CertSource: "panel", Enabled: true}}, Clients: []model.Client{{Email: "alice", Enabled: true, Inbounds: []string{"in"}}}}
	run := func(method, path string, body []byte) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(method, path, bytes.NewReader(body)))
		return w
	}
	save := func() *httptest.ResponseRecorder {
		b, err := json.Marshal(draft)
		if err != nil {
			t.Fatal(err)
		}
		return run(http.MethodPut, "/api/state", b)
	}
	if w := save(); w.Code != http.StatusOK {
		t.Fatalf("save returned %d: %s", w.Code, w.Body.String())
	}
	got := db.Snapshot().Inbounds[0]
	if got.CertFile != pair.CertFile || got.KeyFile != pair.KeyFile || got.SNI != "hub.example.test" || !got.SelfSigned {
		t.Fatal("panel TLS was not resolved")
	}
	w := run(http.MethodGet, "/api/sub-link?client="+db.Snapshot().Clients[0].ID, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "@hub.example.test:443?") || !strings.Contains(w.Body.String(), "sni=hub.example.test") || len(got.CertSHA256) != 64 || !strings.Contains(w.Body.String(), "pcs="+got.CertSHA256) || strings.Contains(w.Body.String(), "allowInsecure") {
		t.Fatal("subscription must use inbound port and certificate name")
	}
	draft.Inbounds[0].NodeID = "exit"
	if w := save(); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("remote panel key reuse accepted: %d", w.Code)
	}
}
