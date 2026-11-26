package gen

import (
	"encoding/json"
	"testing"

	"revhub/internal/model"
)

func xrayInfraState() model.State {
	st := model.Demo()
	st.Infra = &model.InfraConfig{Enabled: true, NodeID: "hub"}
	st.Normalize()
	return st
}

func rulesOf(t *testing.T, st model.State, node string) []any {
	t.Helper()
	raw, err := XrayJSON(st, node)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg["routing"].(map[string]any)["rules"].([]any)
}

func TestXrayHasInfraOutboundOnlyOnInfraNode(t *testing.T) {
	st := xrayInfraState()
	raw, err := XrayJSON(st, "hub")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, o := range cfg["outbounds"].([]any) {
		ob := o.(map[string]any)
		if ob["tag"] == model.TagInfra {
			found = true
			if ob["protocol"] != "freedom" {
				t.Errorf("infra-outbound должен быть freedom, получено %v", ob["protocol"])
			}
			rule := ob["settings"].(map[string]any)["finalRules"].([]any)[0].(map[string]any)
			if rule["action"] != "allow" || rule["ip"].([]any)[0] != st.Infra.Subnet {
				t.Errorf("Freedom должен разрешать только подсеть инфраструктуры: %v", rule)
			}
			if ss, ok := ob["streamSettings"]; ok {
				t.Errorf("infra-outbound не должен иметь mark/streamSettings: %v", ss)
			}
		}
	}
	if !found {
		t.Fatal("на хабе нет infra-outbound")
	}

	raw2, err := XrayJSON(st, "exit-eu")
	if err != nil {
		t.Fatal(err)
	}
	var cfg2 map[string]any
	_ = json.Unmarshal(raw2, &cfg2)
	for _, o := range cfg2["outbounds"].([]any) {
		if o.(map[string]any)["tag"] == model.TagInfra {
			t.Fatal("на узле без инфры не должно быть infra-outbound")
		}
	}
}

func TestXrayInfraRulePrecedesUserRulesAndCatchAll(t *testing.T) {
	st := xrayInfraState()
	// Пользовательский block на весь RFC1918 и catch-all в туннель:
	// адрес инфры всё равно обязан уйти в infra (§5 ТЗ).
	st.Routes = []model.Rule{
		{ID: "r-block", Name: "блок приватных", Enabled: true,
			IP: []string{"10.0.0.0/8", "geoip:private"}, Outbound: model.TagBlock},
		{ID: "r-all", Name: "всё в туннель", Enabled: true, Outbound: "tun:eu"},
	}
	rules := rulesOf(t, st, "hub")
	// rules[0] = api, rules[1] обязан быть инфрой, пользовательские — после.
	if len(rules) < 4 {
		t.Fatalf("правил мало: %v", rules)
	}
	second := rules[1].(map[string]any)
	if second["outboundTag"] != model.TagInfra {
		t.Fatalf("второе правило после api должно быть инфрой: %v", second)
	}
	ips := second["ip"].([]any)
	if ips[0] != "10.89.0.0/24" {
		t.Errorf("правило инфры матчит %v, ожидалась подсеть 10.89.0.0/24", ips)
	}
	third := rules[2].(map[string]any)
	if third["outboundTag"] != model.TagBlock {
		t.Fatalf("пользовательские правила должны идти после инфры: %v", third)
	}
}

func TestXrayNoInfraRuleWithoutInfra(t *testing.T) {
	st := model.Demo() // инфры нет
	rules := rulesOf(t, st, "hub")
	for _, r := range rules {
		if r.(map[string]any)["outboundTag"] == model.TagInfra {
			t.Fatal("без включённой инфры правила быть не должно")
		}
	}
}

func TestValidTagsIncludeInfraOnHub(t *testing.T) {
	st := xrayInfraState()
	if !st.ValidTags("hub")[model.TagInfra] {
		t.Error("ValidTags хаба не содержит infra")
	}
	if st.ValidTags("exit-eu")[model.TagInfra] {
		t.Error("ValidTags чужого узла не должен содержать infra")
	}
	// Пользовательское правило на outbound infra — валидно на хабе
	st.Routes = []model.Rule{{ID: "r", Name: "сервисы в инфру", Enabled: true,
		Domain: []string{"svc.local"}, Outbound: model.TagInfra}}
	if err := st.Validate(); err != nil {
		t.Errorf("правило на infra должно проходить валидацию на хабе: %v", err)
	}
}
