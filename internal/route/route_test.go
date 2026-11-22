package route

import (
	"testing"

	"revhub/internal/model"
)

func TestGeositeReportedAsUncertainNotAsMatch(t *testing.T) {
	st := model.Demo()
	d := Check(st, Query{Node: "hub", User: "alice@revhub", Domain: "sberbank.ru", Port: "443", Network: "tcp"})
	// geosite-правило не блокирует dry-run: точный ответ — по следующему
	// правилу, а geosite попадает в список претендентов.
	if !d.Matched || d.RuleNum != 2 {
		t.Fatalf("ожидался точный матч по правилу №2, получено %+v", d)
	}
	if d.Outbound != "tun:eu" {
		t.Errorf("outbound = %q, ожидался tun:eu", d.Outbound)
	}
	if len(d.Uncertain) != 1 || d.Uncertain[0].RuleNum != 1 {
		t.Fatalf("ожидался один претендент — правило №1, получено %+v", d.Uncertain)
	}
	if d.Uncertain[0].Why != "domain:geosite" {
		t.Errorf("причина = %q", d.Uncertain[0].Why)
	}
}

func TestUncertainOnlyStillAnswersDirect(t *testing.T) {
	st := model.Demo()
	st.Routes = st.Routes[:1] // только правило с geosite
	d := Check(st, Query{Node: "hub", Domain: "example.com"})
	if d.Matched {
		t.Errorf("точного матча нет, получено %+v", d)
	}
	if len(d.Uncertain) != 1 {
		t.Errorf("претендент должен остаться в отчёте, получено %+v", d.Uncertain)
	}
	if d.Outbound != model.TagDirect {
		t.Errorf("outbound = %q, ожидался direct", d.Outbound)
	}
}

func TestFirstMatchWins(t *testing.T) {
	st := model.Demo()
	st.Routes = []model.Rule{
		{ID: "a", Name: "exact", Enabled: true, Domain: []string{"full:example.com"}, Outbound: "tun:eu"},
		{ID: "b", Name: "catch", Enabled: true, Outbound: model.TagDirect},
	}
	d := Check(st, Query{Node: "hub", Domain: "example.com"})
	if d.RuleNum != 1 || d.Outbound != "tun:eu" {
		t.Fatalf("должно сработать первое правило, получено %+v", d)
	}
	d = Check(st, Query{Node: "hub", Domain: "other.example.com"})
	if d.RuleNum != 2 || d.Outbound != model.TagDirect {
		t.Fatalf("должно сработать второе правило, получено %+v", d)
	}
}

func TestDomainForms(t *testing.T) {
	cases := []struct {
		patterns []string
		domain   string
		want     bool
	}{
		{[]string{"full:a.com"}, "a.com", true},
		{[]string{"full:a.com"}, "x.a.com", false},
		{[]string{"domain:a.com"}, "x.a.com", true},
		{[]string{"domain:a.com"}, "nota.com", false},
		{[]string{"regexp:^ads\\."}, "ads.x.net", true},
		{[]string{"keywords"}, "my.keywords.net", true},
	}
	for _, c := range cases {
		got, _ := matchDomain(c.patterns, c.domain)
		if got != c.want {
			t.Errorf("%v vs %q: получено %v, ожидалось %v", c.patterns, c.domain, got, c.want)
		}
	}
}

func TestPortSpec(t *testing.T) {
	if !matchPort("80,443", "443") || !matchPort("1000-2000", "1500") {
		t.Error("не разобрал список/диапазон портов")
	}
	if matchPort("80", "8080") {
		t.Error("ложное совпадение порта")
	}
}

func TestRuleWithForeignOutboundSkipped(t *testing.T) {
	st := model.Demo()
	// На выходном тега tun:eu не существует: туннель начинается на хабе.
	d := Check(st, Query{Node: "exit-eu", Domain: "openai.com", Port: "443", Network: "tcp"})
	if d.Matched {
		t.Fatalf("на выходном нечего матчить, получено %+v", d)
	}
	if d.Outbound != model.TagDirect {
		t.Errorf("outbound = %q, ожидался direct", d.Outbound)
	}
	// Правило «RU → direct» валидно и на выходном (direct там есть),
	// поэтому оно честно остаётся в претендентах.
	if len(d.Uncertain) != 1 || d.Uncertain[0].RuleNum != 1 {
		t.Errorf("ожидался geosite-претендент №1, получено %+v", d.Uncertain)
	}
}

func TestDisabledRuleSkipped(t *testing.T) {
	st := model.Demo()
	st.Routes[0].Enabled = false // выключаем geosite-правило
	d := Check(st, Query{Node: "hub", Domain: "sberbank.ru"})
	if d.RuleNum != 1 || d.Outbound != "tun:eu" {
		t.Fatalf("ожидался матч по оставшемуся правилу (№1), получено %+v", d)
	}
	if len(d.Uncertain) != 0 {
		t.Errorf("выключенное правило не должно попадать в претенденты, получено %+v", d.Uncertain)
	}
}
