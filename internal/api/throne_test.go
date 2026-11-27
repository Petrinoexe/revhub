package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"revhub/internal/model"
	"revhub/internal/store"
)

func TestThroneRouteIsSeparateFromSubscription(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	st := model.Demo()
	st.Infra = &model.InfraConfig{Enabled: true, NodeID: "hub", Subnet: "10.197.3.0/24"}
	st.DNS = &model.DNSConfig{Root: "infra.test", Port: 5353}
	if err := db.Replace(st); err != nil {
		t.Fatal(err)
	}
	c := st.Clients[0]
	handler := (&Server{Store: db, NoAuth: true}).Handler()
	get := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s: %d", path, w.Code)
		}
		return w
	}

	var result map[string]any
	if err := json.Unmarshal(get("/api/sub-link?client="+c.ID).Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	link, _ := result["throne_route"].(string)
	payload, ok := strings.CutPrefix(link, "throne://route/")
	if !ok {
		t.Fatal("missing Throne route link")
	}
	profileJSON, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatal(err)
	}
	var profile struct {
		Kind            string         `json:"kind"`
		Version         int            `json:"v"`
		DefaultOutbound string         `json:"default_outbound"`
		DNS             map[string]any `json:"dns"`
	}
	if err := json.Unmarshal(profileJSON, &profile); err != nil {
		t.Fatal(err)
	}
	if profile.Kind != "throne-route-profile" || profile.Version != 1 || profile.DefaultOutbound != "proxy" {
		t.Fatalf("unexpected Throne route profile: %s", profileJSON)
	}
	if profile.DNS["remote_dns"] != "tcp://10.197.3.1:5353" || profile.DNS["dns_final_out"] != "remote" ||
		profile.DNS["enable_dns_routing"] != false || profile.DNS["fake_dns"] != false {
		t.Fatalf("unexpected per-profile DNS: %+v", profile.DNS)
	}

	w := get("/sub/" + c.SubToken)
	subBody, err := base64.StdEncoding.DecodeString(w.Body.String())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(subBody), "throne://route/") || w.Header().Get("routing") != "" {
		t.Fatal("Throne DNS profile must only be offered for explicit import")
	}
}
