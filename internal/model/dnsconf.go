package model

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// DNSConfig — зона имён внутри клиентской сети WireGuard. Панель сама отдаёт
// A-записи для клиентов по этой зоне, остальное пересылает в upstream.
type DNSConfig struct {
	Root     string   `json:"root"`     // зона, например "vpn.example"; пусто = DNS выключен
	NodeID   string   `json:"node_id"`  // узел, который отдаёт DNS (по умолчанию — с первым WG-инбаундом)
	Panel    string   `json:"panel"`    // метка панели в зоне, по умолчанию "panel"
	Upstream []string `json:"upstream"` // пусто = резолверы хоста из /etc/resolv.conf
	TTL      int      `json:"ttl"`      // секунды, по умолчанию 60
	Port     int      `json:"port"`     // по умолчанию 53
}

const (
	DefaultDNSPort  = 53
	DefaultDNSTTL   = 60
	DefaultDNSPanel = "panel"
)

// PanelConfig — где панель слушает HTTP(S). Пустая строка = только loopback.
type PanelConfig struct {
	Listen string `json:"listen"` // host:port
	// NodeID — узел, на котором слушает панель. Нужен только чтобы открыть
	// порт в firewall именно там (apply собирает порты по узлам).
	NodeID string `json:"node_id"`
	// Expose — осознанное «панель доступна из интернета»: разрешает 0.0.0.0 и
	// внешние адреса. Без него панель держится на петле или внутри WireGuard.
	Expose bool `json:"expose"`
}

const DefaultPanelListen = "127.0.0.1:2096"

// Enabled — зона задана; без неё DNS-сервер не поднимается.
func (d DNSConfig) Enabled() bool { return d.Root != "" }

// FQDN собирает полное имя клиента в зоне.
func (d DNSConfig) FQDN(label string) string {
	if d.Root == "" || label == "" {
		return ""
	}
	return strings.ToLower(label) + "." + strings.ToLower(d.Root)
}

// DNSRecord — одна A-запись зоны.
type DNSRecord struct {
	Name string `json:"name"` // полное имя без точки на конце
	IP   string `json:"ip"`
	Kind string `json:"kind"` // client | panel
	Note string `json:"note,omitempty"`
}

// DNSRecords собирает зону для узла инфраструктуры: имя панели на адресе
// wg-infra и имена инфра-пиров. Клиентские адреса 10.88.x сюда не попадают:
// зона обслуживает инфраструктуру, а клиенты лишь спрашивают её через Xray.
func DNSRecords(st State, nodeID string) []DNSRecord {
	if st.DNS == nil || !st.DNS.Enabled() || st.Infra == nil || !st.Infra.Enabled || st.Infra.NodeID != nodeID {
		return nil
	}
	server := st.Infra.ServerAddress()
	if server == "" {
		return nil
	}
	var out []DNSRecord
	seen := map[string]bool{}
	if panel := st.DNS.FQDN(dnsPanelLabel(*st.DNS)); panel != "" {
		seen[panel] = true
		out = append(out, DNSRecord{Name: panel, IP: server, Kind: "panel", Note: st.Infra.Interface})
	}
	for _, p := range st.InfraPeers {
		if !p.Enabled {
			continue
		}
		label := p.Hostname
		if label == "" {
			label = SlugLabel(p.Name)
		}
		if label == "" {
			label = SlugLabel(p.ID)
		}
		ip := peerIP(p.Address)
		name := st.DNS.FQDN(label)
		if ip == "" || name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, DNSRecord{Name: name, IP: ip, Kind: "infra", Note: p.display()})
	}
	return out
}

func dnsPanelLabel(d DNSConfig) string {
	if d.Panel != "" {
		return d.Panel
	}
	return DefaultDNSPanel
}

// WireGuardAddrs — адреса серверов включённых WG-инбаундов узла и адрес
// wg-infra: единственные адреса, кроме петли, которые панель может занять,
// не открываясь наружу.
func (s State) WireGuardAddrs(nodeID string) []string {
	var out []string
	for _, in := range s.Inbounds {
		if !in.Enabled || in.Kind != InboundWireGuard || in.NodeID != nodeID || in.WireGuard == nil {
			continue
		}
		if addr := in.WireGuard.ServerAddress(); addr != "" {
			out = append(out, addr)
		}
	}
	if s.Infra != nil && s.Infra.Enabled && s.Infra.NodeID == nodeID {
		if addr := s.Infra.ServerAddress(); addr != "" {
			for _, prev := range out {
				if prev == addr {
					return out
				}
			}
			out = append(out, addr)
		}
	}
	return out
}

// clientLabel — метка имени клиента в зоне: hostname, иначе начало email.
func clientLabel(c Client) string {
	if c.Hostname != "" {
		return c.Hostname
	}
	return hostnameFromEmail(c.Email, c.ID)
}

// hostnameFromEmail — метка из email: "alice@revhub" → "alice".
func hostnameFromEmail(email, fallback string) string {
	local := email
	if i := strings.IndexByte(local, '@'); i > 0 {
		local = local[:i]
	}
	if label := SlugLabel(local); label != "" {
		return label
	}
	if label := SlugLabel(fallback); label != "" {
		return label
	}
	return "client"
}

// NormalizeName приводит имя DNS к сравнимому виду: нижний регистр, без точки.
func NormalizeName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// SlugLabel приводит строку к метке DNS: a-z, 0-9, дефис; не длиннее 63.
func SlugLabel(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case b.Len() > 0 && !dash:
			b.WriteByte('-')
			dash = true
		}
		if b.Len() >= 63 {
			break
		}
	}
	return strings.Trim(b.String(), "-")
}

// normalizeDNSHostnames проставляет метки клиентам и разводит совпадения
// суффиксом -2, -3: два клиента с email alice@a и alice@b не должны делить имя.
func (s *State) normalizeDNSHostnames() {
	used := map[string]bool{}
	for i := range s.Clients {
		c := &s.Clients[i]
		label := SlugLabel(c.Hostname)
		if label == "" {
			label = hostnameFromEmail(c.Email, c.ID)
		}
		base := label
		for n := 2; used[label]; n++ {
			suffix := "-" + strconv.Itoa(n)
			if len(base)+len(suffix) > 63 {
				base = base[:63-len(suffix)]
			}
			label = strings.Trim(base+suffix, "-")
		}
		c.Hostname = label
		used[label] = true
	}
}

func (s *State) normalizeDNS() {
	if s.Panel == nil {
		s.Panel = &PanelConfig{}
	}
	if s.Panel.Listen == "" {
		s.Panel.Listen = DefaultPanelListen
	}
	if s.Panel.NodeID == "" && len(s.Nodes) > 0 {
		s.Panel.NodeID = s.Nodes[0].ID
	}
	if s.DNS == nil {
		return
	}
	if s.DNS.Port == 0 {
		s.DNS.Port = DefaultDNSPort
	}
	if s.DNS.TTL == 0 {
		s.DNS.TTL = DefaultDNSTTL
	}
	if s.DNS.Panel == "" {
		s.DNS.Panel = DefaultDNSPanel
	}
	if s.DNS.NodeID == "" {
		// DNS обслуживает инфраструктурную сеть: живёт на узле wg-infra.
		if s.Infra != nil && s.Infra.Enabled && s.Infra.NodeID != "" {
			s.DNS.NodeID = s.Infra.NodeID
		}
	}
	s.DNS.Root = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s.DNS.Root)), ".")
}

func (s State) validateDNS(add func(string, ...any)) {
	if s.DNS == nil || !s.DNS.Enabled() {
		return
	}
	if !validDomain(s.DNS.Root) {
		add("DNS: зона %q — не доменное имя (метки через точку, a-z, 0-9, дефис)", s.DNS.Root)
	}
	if !validLabel(dnsPanelLabel(*s.DNS)) {
		add("DNS: метка панели %q — не метка DNS", s.DNS.Panel)
	}
	if s.DNS.Port <= 0 || s.DNS.Port > 65535 {
		add("DNS: некорректный порт %d", s.DNS.Port)
	}
	if s.DNS.NodeID != "" {
		if s.Infra == nil || !s.Infra.Enabled || s.Infra.NodeID != s.DNS.NodeID {
			add("DNS: узел %q не обслуживает сеть инфраструктуры (DNS живёт на узле wg-infra)", s.DNS.NodeID)
		}
	}
	if s.DNS.TTL < 0 || s.DNS.TTL > 86400 {
		add("DNS: TTL %d вне 0..86400", s.DNS.TTL)
	}
	for _, up := range s.DNS.Upstream {
		if !validResolver(up) {
			add("DNS: upstream %q — нужен IP или IP:порт", up)
		}
	}
	names := map[string]string{}
	for _, c := range s.Clients {
		label := c.Hostname
		if !validLabel(label) {
			add("клиент %s: имя %q — не метка DNS", c.Email, label)
			continue
		}
		if prev, ok := names[label]; ok {
			add("DNS: имя %q занято дважды (%s и %s)", label, prev, c.Email)
			continue
		}
		names[label] = c.Email
	}
}

func validLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}
	for i, r := range label {
		ok := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' && i > 0 && i < len(label)-1
		if !ok {
			return false
		}
	}
	return true
}

func validDomain(domain string) bool {
	if domain == "" || len(domain) > 253 {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if !validLabel(label) {
			return false
		}
	}
	return true
}

// validResolver принимает "1.1.1.1" и "1.1.1.1:53" (в том числе IPv6).
func validResolver(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	if host, port, err := net.SplitHostPort(s); err == nil {
		if _, err := netip.ParseAddr(host); err != nil {
			return false
		}
		p, err := strconv.Atoi(port)
		return err == nil && p > 0 && p <= 65535
	}
	return false
}

// ResolverAddr — адрес upstream: порт по умолчанию 53.
func ResolverAddr(s string) (string, error) {
	if addr, err := netip.ParseAddr(s); err == nil {
		return net.JoinHostPort(addr.String(), strconv.Itoa(DefaultDNSPort)), nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", fmt.Errorf("upstream %q: нужен IP или IP:порт", s)
	}
	return net.JoinHostPort(host, port), nil
}

// Port — TCP-порт панели (2096, если в адресе мусор).
func (p *PanelConfig) Port() int {
	_, port, err := net.SplitHostPort(p.Addr())
	if err != nil {
		return 2096
	}
	n, err := strconv.Atoi(port)
	if err != nil || n <= 0 || n > 65535 {
		return 2096
	}
	return n
}

// Exposed — панель слушает не только петлю.
func (p *PanelConfig) Exposed() bool {
	return p != nil && !p.LoopbackOnly()
}

// Addr — nil-безопасно: состояние из старого файла может не иметь блока panel.
func (p *PanelConfig) Addr() string {
	if p == nil || p.Listen == "" {
		return DefaultPanelListen
	}
	return p.Listen
}

// LoopbackOnly — панель доступна только с самой машины.
func (p *PanelConfig) LoopbackOnly() bool {
	host, _, err := net.SplitHostPort(p.Addr())
	if err != nil {
		return false
	}
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func (s State) validatePanel(add func(string, ...any)) {
	if s.Panel == nil {
		return
	}
	host, port, err := net.SplitHostPort(s.Panel.Addr())
	if err != nil || host == "" {
		add("панель: адрес %q — нужен host:port", s.Panel.Addr())
		return
	}
	if p, err := strconv.Atoi(port); err != nil || p <= 0 || p > 65535 {
		add("панель: некорректный порт %q", port)
	}
	if s.Panel.NodeID != "" {
		found := false
		for _, n := range s.Nodes {
			if n.ID == s.Panel.NodeID {
				found = true
				break
			}
		}
		if !found {
			add("панель: узел %q не найден", s.Panel.NodeID)
		}
	}

	addr, ipErr := netip.ParseAddr(host)
	if ipErr == nil && addr.IsLoopback() {
		if s.Panel.Expose {
			add("панель: expose=true, но адрес %s — только петля (убери expose или задай адрес)", host)
		}
		return // loopback — законный режим (доступ через SSH-туннель)
	}
	if ipErr != nil {
		return // имя хоста: привязка к интерфейсу проверяется при запуске
	}

	if addr.IsUnspecified() {
		if !s.Panel.Expose {
			add("панель: адрес %s слушает все интерфейсы, то есть открыт наружу — "+
				"поставь panel.expose=true (вкладка «Панель» или revhub panel expose)", host)
		}
		return
	}

	onWireGuard := false
	for _, addr := range s.WireGuardAddrs(s.Panel.NodeID) {
		if host == addr {
			onWireGuard = true
			break
		}
	}
	if onWireGuard && s.Panel.Expose {
		add("панель: адрес %s — внутри WireGuard, expose для него не нужен", host)
		return
	}
	if !onWireGuard && !s.Panel.Expose {
		add("панель: адрес %q не принадлежит ни одному WireGuard-интерфейсу узла — "+
			"чтобы открыть её наружу, поставь panel.expose=true", host)
	}
}

func hasString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// peerIP отрезает маску от адреса пира: "10.88.0.2/32" → "10.88.0.2".
func peerIP(address string) string {
	if address == "" {
		return ""
	}
	if addr, err := netip.ParsePrefix(address); err == nil {
		return addr.Addr().String()
	}
	if addr, err := netip.ParseAddr(address); err == nil {
		return addr.String()
	}
	return ""
}
