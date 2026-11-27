// Package route — dry-run маршрутизации: какой исходящий получит конкретный
// запрос, и какое правило сработало. Повторяет семантику xray «первый матч»,
// не запуская ядро (см. docs/DECISIONS.md, ADR-5).
//
// Правила с непроверяемыми локально условиями (geoip:/geosite:) не
// останавливают проверку: ответ сообщает и точный матч, и список правил выше,
// которые могут его перехватить. Иначе одна geosite-строка в начале списка
// делала бы dry-run бесполезным.
package route

import (
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"revhub/internal/model"
)

type Query struct {
	Node    string `json:"node"`
	User    string `json:"user"`
	Inbound string `json:"inbound"`
	Domain  string `json:"domain"`
	IP      string `json:"ip"`
	Port    string `json:"port"`
	Network string `json:"network"`
}

type Uncertain struct {
	RuleNum  int    `json:"rule_num"`
	RuleName string `json:"rule_name"`
	Why      string `json:"why"`
}

type Decision struct {
	Matched   bool        `json:"matched"`
	RuleNum   int         `json:"rule_num"` // 1-based, как в UI; 0 = ни одно правило
	RuleName  string      `json:"rule_name"`
	Outbound  string      `json:"outbound"`
	Reason    string      `json:"reason"`
	Uncertain []Uncertain `json:"uncertain,omitempty"`
}

// Check возвращает точный матч и правила-претенденты с непроверяемыми
// условиями, стоящие выше него.
func Check(st model.State, q Query) Decision {
	if addr, port := st.InfraDNSAddress(q.Node); addr != "" {
		if q.IP == addr && q.Port == strconv.Itoa(port) && (q.Network == "tcp" || q.Network == "udp") {
			return Decision{Matched: true, RuleName: "DNS инфраструктуры", Outbound: model.TagInfra,
				Reason: "запрос к адресу и порту dnsmasq идёт через Freedom infra"}
		}
		if q.Port == "53" && (q.Network == "tcp" || q.Network == "udp") {
			for _, in := range st.Inbounds {
				if in.Enabled && in.NodeID == q.Node && in.Tag == q.Inbound {
					return Decision{Matched: true, RuleName: "DNS инфраструктуры", Outbound: model.TagInfraDNS,
						Reason: "клиентский DNS на порту 53 перенаправляется в dnsmasq"}
				}
			}
		}
		if matched, _ := matchDomain([]string{"domain:" + st.DNS.Root}, q.Domain); matched {
			return Decision{Matched: true, RuleName: "зона инфраструктуры", Outbound: model.TagInfra,
				Reason: "имя в зоне " + st.DNS.Root + " разрешается через dnsmasq"}
		}
	}
	// Системное правило xray: инфра-подсеть → freedom infra — стоит в конфиге
	// выше всех пользовательских правил (§5 ТЗ). Проверяем его до их цикла,
	// иначе dry-run врал бы против реального поведения ядра.
	if subnet := st.InfraSubnet(q.Node); subnet != "" && q.IP != "" {
		if _, ipnet, err := net.ParseCIDR(subnet); err == nil && ipnet.Contains(net.ParseIP(q.IP)) {
			return Decision{Matched: true, RuleNum: 0, RuleName: "инфраструктура",
				Outbound: model.TagInfra,
				Reason:   "адрес в инфра-подсети " + subnet + " → freedom infra (приоритет над правилами и блокировкой приватных)"}
		}
	}
	// Системное правило выхода клиентской сети: inbound.egress рендерится в
	// routing Xray выше пользовательских правил. Личный client.egress (по
	// source-адресу) в dry-run не выражается — в ответе это оговорено.
	if q.Inbound != "" && q.Node != "" {
		if tags := st.ValidTags(q.Node); len(tags) > 0 {
			for _, in := range st.Inbounds {
				if in.Enabled && in.NodeID == q.Node && in.Tag == q.Inbound && in.Egress != "" && tags[in.Egress] {
					return Decision{Matched: true, RuleNum: 0, RuleName: "выход сети " + in.Tag,
						Outbound: in.Egress,
						Reason:   "inbound " + in.Tag + " → " + in.Egress + " (выше правил; личный выход клиента может переопределить)"}
				}
			}
		}
	}
	var unc []Uncertain
	num := 0
	for _, r := range st.Routes {
		if !r.Enabled || (r.NodeID != "" && q.Node != "" && r.NodeID != q.Node) {
			continue
		}
		// Правило, чей исходящий на этом узле не существует (например, туннель
		// начинается в другом месте), не рендерится — значит и не матчится.
		if q.Node != "" && !st.ValidTags(q.Node)[r.Outbound] {
			continue
		}
		num++
		ok, unknown, why := match(r, q)
		if !ok {
			continue
		}
		if unknown {
			unc = append(unc, Uncertain{RuleNum: num, RuleName: r.Name, Why: why})
			continue
		}
		return Decision{Matched: true, RuleNum: num, RuleName: r.Name,
			Outbound: r.Outbound, Reason: why, Uncertain: unc}
	}
	return Decision{Matched: false, Outbound: model.TagDirect,
		Reason: "ни одно правило не совпало → сработает заглушка direct", Uncertain: unc}
}

func match(r model.Rule, q Query) (ok, unknown bool, why string) {
	var parts []string
	unknownWhy := ""

	if len(r.User) > 0 {
		if q.User == "" || !contains(r.User, q.User) {
			return false, false, ""
		}
		parts = append(parts, "user="+q.User)
	}
	if len(r.Inbound) > 0 {
		if q.Inbound == "" || !contains(r.Inbound, q.Inbound) {
			return false, false, ""
		}
		parts = append(parts, "inbound="+q.Inbound)
	}
	if len(r.Domain) > 0 {
		if q.Domain == "" {
			return false, false, ""
		}
		m, unk := matchDomain(r.Domain, q.Domain)
		if !m && !unk {
			return false, false, ""
		}
		if !m && unk {
			unknownWhy = "domain:geosite"
		}
		parts = append(parts, "domain="+q.Domain)
	}
	if len(r.IP) > 0 {
		if q.IP == "" {
			return false, false, ""
		}
		m, unk := matchIP(r.IP, q.IP)
		if !m && !unk {
			return false, false, ""
		}
		if !m && unk {
			unknownWhy = "ip:geoip"
		}
		parts = append(parts, "ip="+q.IP)
	}
	if r.Port != "" {
		if q.Port == "" || !matchPort(r.Port, q.Port) {
			return false, false, ""
		}
		parts = append(parts, "port="+q.Port)
	}
	if r.Network != "" {
		if q.Network == "" || !contains(strings.Split(r.Network, ","), q.Network) {
			return false, false, ""
		}
		parts = append(parts, "network="+q.Network)
	}
	if len(parts) == 0 {
		return true, false, "правило без условий (ловит всё)"
	}
	if unknownWhy != "" {
		return true, true, unknownWhy
	}
	return true, false, strings.Join(parts, ", ")
}

func matchDomain(patterns []string, domain string) (matched, unknown bool) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		switch {
		case strings.HasPrefix(p, "geosite:"):
			unknown = true
		case strings.HasPrefix(p, "full:"):
			if domain == strings.TrimPrefix(p, "full:") {
				matched = true
			}
		case strings.HasPrefix(p, "domain:"):
			d := strings.TrimPrefix(p, "domain:")
			if domain == d || strings.HasSuffix(domain, "."+d) {
				matched = true
			}
		case strings.HasPrefix(p, "regexp:"):
			if re, err := regexp.Compile(strings.TrimPrefix(p, "regexp:")); err == nil && re.MatchString(domain) {
				matched = true
			}
		default:
			if strings.Contains(domain, p) {
				matched = true
			}
		}
		if matched {
			return true, false
		}
	}
	return false, unknown
}

func matchIP(patterns []string, ip string) (matched, unknown bool) {
	addr := net.ParseIP(ip)
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		switch {
		case strings.HasPrefix(p, "geoip:"):
			unknown = true
		case strings.Contains(p, "/"):
			if _, ipnet, err := net.ParseCIDR(p); err == nil && addr != nil && ipnet.Contains(addr) {
				matched = true
			}
		default:
			if addr != nil && net.ParseIP(p) != nil && addr.Equal(net.ParseIP(p)) {
				matched = true
			}
		}
		if matched {
			return true, false
		}
	}
	return false, unknown
}

func matchPort(spec, port string) bool {
	p, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			ab := strings.SplitN(part, "-", 2)
			lo, e1 := strconv.Atoi(strings.TrimSpace(ab[0]))
			hi, e2 := strconv.Atoi(strings.TrimSpace(ab[1]))
			if e1 == nil && e2 == nil && p >= lo && p <= hi {
				return true
			}
			continue
		}
		if v, err := strconv.Atoi(part); err == nil && v == p {
			return true
		}
	}
	return false
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// SortedUncertain — для стабильного вывода в API/UI.
func (d Decision) SortedUncertain() []Uncertain {
	out := append([]Uncertain(nil), d.Uncertain...)
	sort.Slice(out, func(i, j int) bool { return out[i].RuleNum < out[j].RuleNum })
	return out
}
