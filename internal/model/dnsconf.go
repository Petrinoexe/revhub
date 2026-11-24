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

// DNSRecords собирает зону для узла: имена клиентов, у которых есть пир на
// WireGuard-инбаунде этого узла, плюс имя самой панели (адрес интерфейса).
// Имена с других узлов сюда не попадают: из одной подсети они недостижимы.
func DNSRecords(st State, nodeID string) []DNSRecord {
	if st.DNS == nil || !st.DNS.Enabled() {
		return nil
	}
	var out []DNSRecord
	seen := map[string]bool{}
	for _, in := range st.Inbounds {
		if in.NodeID != nodeID || !in.Enabled || in.Kind != InboundWireGuard || in.WireGuard == nil {
			continue
		}
		if panel := st.DNS.FQDN(dnsPanelLabel(*st.DNS)); panel != "" && !seen[panel] {
			if addr := in.WireGuard.ServerAddress(); addr != "" {
				seen[panel] = true
				out = append(out, DNSRecord{Name: panel, IP: addr, Kind: "panel", Note: in.Tag})
			}
		}
		for _, c := range st.Clients {
			if !c.Enabled || c.Expired() || !hasString(c.Inbounds, in.ID) {
				continue
			}
			peer, ok := c.WireGuard[in.ID]
			if !ok {
				continue
			}
			ip := peerIP(peer.Address)
			name := st.DNS.FQDN(clientLabel(c))
			if ip == "" || name == "" || seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, DNSRecord{Name: name, IP: ip, Kind: "client", Note: c.Email})
		}
	}
	return out
}

func dnsPanelLabel(d DNSConfig) string {
	if d.Panel != "" {
		return d.Panel
	}
	return DefaultDNSPanel
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
		// DNS живёт там, где есть клиентская сеть: первый включённый WG-инбаунд.
		for _, in := range s.Inbounds {
			if in.Enabled && in.Kind == InboundWireGuard {
				s.DNS.NodeID = in.NodeID
				break
			}
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
		ok := false
		for _, in := range s.Inbounds {
			if in.NodeID == s.DNS.NodeID && in.Enabled && in.Kind == InboundWireGuard {
				ok = true
				break
			}
		}
		if !ok {
			add("DNS: узел %q не отдаёт ни одного включённого WireGuard-инбаунда", s.DNS.NodeID)
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
	if addr, err := netip.ParseAddr(host); err == nil && addr.IsLoopback() {
		return // loopback — законный режим (доступ через SSH-туннель)
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return // имя хоста: привязка к интерфейсу проверяется при запуске
	}
	found := false
	for _, in := range s.Inbounds {
		if in.Kind != InboundWireGuard || in.WireGuard == nil || !in.Enabled {
			continue
		}
		if p, ok := wireGuardSubnet(in.WireGuard.Subnet); ok && p.Contains(netip.MustParseAddr(host)) &&
			host == in.WireGuard.ServerAddress() {
			found = true
			break
		}
	}
	if !found {
		add("панель: адрес %q не принадлежит ни одному WireGuard-интерфейсу узла — снаружи панель не откроется", host)
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
