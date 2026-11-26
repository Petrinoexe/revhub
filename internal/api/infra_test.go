package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"revhub/internal/model"
	"revhub/internal/store"
)

func TestInfraPeerConfigEndpoint(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	handler := (&Server{Store: db, NoAuth: true, OutDir: t.TempDir()}).Handler()

	st := model.State{
		Nodes: []model.Node{{ID: "hub", PublicAddr: "hub.example.com:2096"}},
		Infra: &model.InfraConfig{Enabled: true, NodeID: "hub"},
		InfraPeers: []model.InfraPeer{
			{Name: "srv-db", Enabled: true},
			{Name: "off", Enabled: false},
		},
	}
	body, _ := json.Marshal(st)
	put := httptest.NewRecorder()
	handler.ServeHTTP(put, httptest.NewRequest(http.MethodPut, "/api/state", bytes.NewReader(body)))
	if put.Code != http.StatusOK {
		t.Fatalf("сохранение: %d %s", put.Code, put.Body.String())
	}
	saved := db.Snapshot()
	peer := saved.InfraPeers[0]
	if peer.ID == "" || peer.Address == "" || peer.PrivateKey == "" {
		t.Fatalf("пир не нормализован: %+v", peer)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/infra/"+peer.ID+"/wg-conf", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("конфиг пира: %d %s", w.Code, w.Body.String())
	}
	text := w.Body.String()
	for _, want := range []string{"PrivateKey = " + peer.PrivateKey, "Address = " + peer.Address,
		"PublicKey = " + saved.Infra.PublicKey, "AllowedIPs = 0.0.0.0/0", "Endpoint = hub.example.com:51840"} {
		if !strings.Contains(text, want) {
			t.Errorf("в конфиге нет %q\n%s", want, text)
		}
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("конфиг содержит приватный ключ и не должен кешироваться")
	}

	// Выключенный пир конфиг не получает.
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/infra/"+saved.InfraPeers[1].ID+"/wg-conf", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("выключенный пир: статус %d", w.Code)
	}
}
