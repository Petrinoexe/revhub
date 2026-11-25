package model

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
)

const (
	DefaultWireGuardSubnet = "10.88.0.0/24"
	DefaultWireGuardMTU    = 1420
	// DNS отдаётся клиенту в его wg-quick конфиге: без него полный туннель
	// уводит весь трафик, а резолвинг остаётся у провайдера (утечка + часть
	// сайтов недоступна по геолокации).
	DefaultWireGuardDNS = "1.1.1.1, 1.0.0.1"
)

type WireGuardInbound struct {
	Subnet     string `json:"subnet"`
	DNS        string `json:"dns"` // список IP через запятую для клиентских конфигов
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

type WireGuardPeer struct {
	Address      string `json:"address"` // /32
	PrivateKey   string `json:"private_key"`
	PublicKey    string `json:"public_key"`
	PresharedKey string `json:"preshared_key"`
}

func (in *Inbound) normalizeWireGuard() {
	if in.Listen == "" {
		in.Listen = "0.0.0.0"
	}
	if in.Port == 0 {
		in.Port = 51820
	}
	if in.WireGuard == nil {
		in.WireGuard = &WireGuardInbound{}
	}
	wg := in.WireGuard
	if wg.Subnet == "" {
		wg.Subnet = DefaultWireGuardSubnet
	}
	if wg.DNS == "" {
		wg.DNS = DefaultWireGuardDNS
	}
	fillWGKeys(&wg.PrivateKey, &wg.PublicKey)
}

// SharedSubnet — общая сеть: клиенты, хаб и выходы в одной подсети.
func (s State) SharedSubnet() string {
	for _, in := range s.Inbounds {
		if in.Kind == InboundWireGuard && in.WireGuard != nil && in.WireGuard.Subnet != "" {
			return in.WireGuard.Subnet
		}
	}
	return DefaultWireGuardSubnet
}

// assignWireGuardPorts разводит UDP-порты клиентских сетей. Конфликт с
// туннелем на том же узле (он тоже слушает UDP) или с другим инбаундом — не
// повод отказывать в создании инбаунда: порт просто сдвигается на свободный,
// а панель покажет его после сохранения.
func (s *State) assignWireGuardPorts() {
	taken := map[string]map[int]bool{}
	mark := func(node string, port int) {
		if node == "" || port <= 0 {
			return
		}
		if taken[node] == nil {
			taken[node] = map[int]bool{}
		}
		taken[node][port] = true
	}
	for _, t := range s.Tunnels {
		if !t.Enabled || (t.Kind != TunnelWG && t.Kind != TunnelWGReverse) {
			continue
		}
		mark(t.ListenerNode(), t.ListenPort)
	}
	for i := range s.Inbounds {
		in := &s.Inbounds[i]
		if in.Kind != InboundWireGuard {
			continue
		}
		ports := taken[in.NodeID]
		if ports == nil {
			ports = map[int]bool{}
			taken[in.NodeID] = ports
		}
		if in.Port > 0 && !ports[in.Port] {
			ports[in.Port] = true
			continue
		}
		for p := 51820; p < 65535; p++ {
			if !ports[p] {
				ports[p] = true
				in.Port = p
				break
			}
		}
	}
}

// assignTunnelAddresses раскладывает концы туннелей по общей сети: хаб .200+,
// выходы .250+. Отдельная /30 больше не нужна: маршруты и правила считаются
// по одной сети, а адрес выхода — обычный адрес в ней (к нему и маршрутят
// клиентов). Занятые адреса клиентов и адрес хаба обходим.
func (s *State) assignTunnelAddresses() {
	_, ipnet, err := net.ParseCIDR(s.SharedSubnet())
	if err != nil || ipnet == nil {
		return
	}
	base := ipnet.IP.To4()
	if base == nil {
		return
	}
	taken := map[byte]bool{1: true} // .1 — хаб
	for _, in := range s.Inbounds {
		if in.Kind != InboundWireGuard || in.WireGuard == nil {
			continue
		}
		if ip := net.ParseIP(in.WireGuard.ServerAddress()); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				taken[v4[3]] = true
			}
		}
	}
	for _, c := range s.Clients {
		for _, p := range c.WireGuard {
			if ip := net.ParseIP(p.Address); ip != nil {
				if v4 := ip.To4(); v4 != nil {
					taken[v4[3]] = true
				}
			}
		}
	}
	next := func(from int) byte {
		for i := from; i < 255; i++ {
			if !taken[byte(i)] {
				taken[byte(i)] = true
				return byte(i)
			}
		}
		return 0
	}
	for i := range s.Tunnels {
		t := &s.Tunnels[i]
		if t.Kind != TunnelWG && t.Kind != TunnelWGReverse {
			continue
		}
		if t.FromAddr == "" {
			if b := next(200); b != 0 {
				ip := make(net.IP, 4)
				copy(ip, base)
				ip[3] = b
				t.FromAddr = ip.String()
			}
		}
		if t.ToAddr == "" {
			if b := next(250); b != 0 {
				ip := make(net.IP, 4)
				copy(ip, base)
				ip[3] = b
				t.ToAddr = ip.String()
			}
		}
	}
}

func (s *State) normalizeWireGuardPeers() {
	inbounds := make(map[string]*WireGuardInbound)
	used := make(map[string]map[string]bool)
	for _, in := range s.Inbounds {
		if in.Kind == InboundWireGuard {
			inbounds[in.ID] = in.WireGuard
			used[in.ID] = make(map[string]bool)
		}
	}
	for i := range s.Clients {
		c := &s.Clients[i]
		for id, peer := range c.WireGuard {
			if inbounds[id] == nil || !slices.Contains(c.Inbounds, id) {
				delete(c.WireGuard, id)
				continue
			}
			used[id][peer.Address] = true
		}
	}
	for i := range s.Clients {
		c := &s.Clients[i]
		for _, id := range c.Inbounds {
			wg := inbounds[id]
			if wg == nil {
				continue
			}
			peer := c.WireGuard[id]
			if peer.Address == "" {
				peer.Address = nextWireGuardAddress(wg.Subnet, used[id])
				if peer.Address == "" {
					continue // Validate reports the invalid or exhausted pool.
				}
				used[id][peer.Address] = true
			}
			fillWGKeys(&peer.PrivateKey, &peer.PublicKey)
			if peer.PresharedKey == "" {
				var key [32]byte
				if _, err := rand.Read(key[:]); err == nil {
					peer.PresharedKey = base64.StdEncoding.EncodeToString(key[:])
				}
			}
			if c.WireGuard == nil {
				c.WireGuard = make(map[string]WireGuardPeer)
			}
			c.WireGuard[id] = peer
		}
	}
}

func fillWGKeys(private, public *string) {
	if *private == "" && *public == "" {
		if priv, pub, err := GenWGKeys(); err == nil {
			*private, *public = priv, pub
		}
	} else if *public == "" {
		*public = wgPublicKey(*private)
	}
}

func wgPublicKey(private string) string {
	b, err := base64.StdEncoding.DecodeString(private)
	if err != nil {
		return ""
	}
	key, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
}

func wireGuardSubnet(subnet string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(subnet)
	return p, err == nil && p.Addr().Is4() && p == p.Masked() && p.Bits() >= 8 && p.Bits() <= 30
}

func nextWireGuardAddress(subnet string, used map[string]bool) string {
	p, ok := wireGuardSubnet(subnet)
	if !ok {
		return ""
	}
	for ip := p.Addr().Next().Next(); p.Contains(ip.Next()); ip = ip.Next() {
		address := netip.PrefixFrom(ip, 32).String()
		if !used[address] {
			return address
		}
	}
	return ""
}

// ServerAddress возвращает первый адрес подсети, зарезервированный для Xray.
func (wg WireGuardInbound) ServerAddress() string {
	p, ok := wireGuardSubnet(wg.Subnet)
	if !ok {
		return ""
	}
	return p.Addr().Next().String()
}

// ServerAddressPrefix — адрес сервера с маской подсети (для wg-quick:
// 10.88.0.1/24). Пусто, если подсеть невалидна.
func (wg WireGuardInbound) ServerAddressPrefix() string {
	p, ok := wireGuardSubnet(wg.Subnet)
	if !ok {
		return ""
	}
	return netip.PrefixFrom(p.Addr().Next(), p.Bits()).String()
}

// WGInterface — имя ядерного интерфейса клиентского инбаунда. Имена сетевых
// интерфейсов ограничены 15 символами, поэтому длинный тег уходит в хеш.
func (in Inbound) WGInterface() string {
	name := "wgc-" + in.Tag
	if len(name) <= 15 && !strings.ContainsFunc(name, func(c rune) bool {
		return !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_=+.-", c))
	}) {
		return name
	}
	sum := sha256.Sum256([]byte(in.ID + "/" + in.Tag))
	return fmt.Sprintf("wgc-%x", sum[:5])
}

// assignWireGuardSubnets выдаёт подсети клиентским инбаундам, у которых она не
// задана: первый свободный 10.88.N.0/24 на узле. Две одинаковые подсети на
// одном узле — это одна таблица маршрутов с неоднозначными адресами, поэтому
// новому инбаунду достаётся следующий номер, а не общий дефолт.
func (s *State) assignWireGuardSubnets() {
	used := make([]netip.Prefix, 0, len(s.Inbounds))
	for i := range s.Inbounds {
		in := &s.Inbounds[i]
		if in.Kind != InboundWireGuard {
			continue
		}
		if in.WireGuard == nil {
			in.WireGuard = &WireGuardInbound{}
		}
		if p, ok := wireGuardSubnet(in.WireGuard.Subnet); ok {
			used = append(used, p)
			continue
		}
		for n := 0; n < 256; n++ {
			cand, err := netip.ParsePrefix(fmt.Sprintf("10.88.%d.0/24", n))
			if err != nil {
				break
			}
			free := true
			for _, u := range used {
				if u.Overlaps(cand) {
					free = false
					break
				}
			}
			if !free {
				continue
			}
			in.WireGuard.Subnet = cand.String()
			used = append(used, cand)
			break
		}
	}
}

// validateEgress проверяет, куда инбаунд выпускает клиентов: напрямую через
// этот узел или в туннель, который начинается здесь же.
func validateEgress(s State, in Inbound) error {
	if in.Egress == "" || in.Egress == TagDirect {
		return nil
	}
	name, ok := strings.CutPrefix(in.Egress, TagTunnel)
	if !ok {
		return fmt.Errorf("выход %q: нужен direct или tun:<имя>", in.Egress)
	}
	for _, t := range s.Tunnels {
		if t.Name == name && t.Enabled && t.FromNode == in.NodeID {
			return nil
		}
	}
	return fmt.Errorf("выход %q: нет включённого туннеля %s на узле %s", in.Egress, name, in.NodeID)
}

func (s State) validateWireGuard(in Inbound, add func(string, ...any)) {
	if ip, err := netip.ParseAddr(in.Listen); err != nil || ip.Zone() != "" {
		add("инбаунд %s: WireGuard требует IP в поле listen", in.Tag)
	}
	wg := in.WireGuard
	if wg == nil {
		add("инбаунд %s: нет настроек WireGuard", in.Tag)
		return
	}
	p, ok := wireGuardSubnet(wg.Subnet)
	if !ok {
		add("инбаунд %s: нужна IPv4-подсеть WireGuard от /8 до /30", in.Tag)
	} else {
		// Клиенты всех инбаундов одного узла живут в его таблице маршрутов:
		// две одинаковые подсети (или пересечение) сделают адреса неоднозначными.
		for _, other := range s.Inbounds {
			if other.ID == in.ID || other.Kind != InboundWireGuard || other.NodeID != in.NodeID || other.WireGuard == nil {
				continue
			}
			q, ok := wireGuardSubnet(other.WireGuard.Subnet)
			if !ok {
				continue
			}
			if p.Overlaps(q) {
				add("инбаунд %s: подсеть %s пересекается с инбаундом %s (%s) на узле %s",
					in.Tag, wg.Subnet, other.Tag, other.WireGuard.Subnet, in.NodeID)
			}
		}
	}
	if err := validateEgress(s, in); err != nil {
		add("инбаунд %s: %v", in.Tag, err)
	}
	if wg.DNS != "" {
		for _, part := range strings.Split(wg.DNS, ",") {
			// Клиентский конфиг уходит как есть: опечатка в DNS оставит
			// клиента без резолвера при живом туннеле.
			if _, err := netip.ParseAddr(strings.TrimSpace(part)); err != nil {
				add("инбаунд %s: DNS клиентов — IP-адреса через запятую", in.Tag)
				break
			}
		}
	}
	if pub := wgPublicKey(wg.PrivateKey); pub == "" || pub != wg.PublicKey {
		add("инбаунд %s: неверная пара ключей WireGuard", in.Tag)
	}
	addresses := make(map[netip.Addr]bool)
	keys := map[string]bool{wg.PublicKey: true}
	for _, c := range s.Clients {
		if !slices.Contains(c.Inbounds, in.ID) {
			continue
		}
		peer, exists := c.WireGuard[in.ID]
		if !exists {
			add("инбаунд %s: нет свободного адреса WireGuard для клиента %s", in.Tag, c.Email)
			continue
		}
		addr, err := netip.ParsePrefix(peer.Address)
		ip := addr.Addr()
		if err != nil || addr.Bits() != 32 || !p.Contains(ip) || ip == p.Addr() || ip == p.Addr().Next() || !p.Contains(ip.Next()) || addresses[ip] {
			add("инбаунд %s: у клиента %s неверный или повторяющийся адрес WireGuard", in.Tag, c.Email)
		}
		addresses[ip] = true
		if pub := wgPublicKey(peer.PrivateKey); pub == "" || pub != peer.PublicKey || keys[pub] {
			add("инбаунд %s: у клиента %s неверная или повторяющаяся пара ключей WireGuard", in.Tag, c.Email)
		}
		keys[peer.PublicKey] = true
		if key, err := base64.StdEncoding.DecodeString(peer.PresharedKey); err != nil || len(key) != 32 {
			add("инбаунд %s: у клиента %s неверный предварительный ключ WireGuard", in.Tag, c.Email)
		}
	}
}

func (s State) validateWireGuardPort(index int, add func(string, ...any)) {
	in := s.Inbounds[index]
	if !in.Enabled {
		return
	}
	for _, tunnel := range s.Tunnels {
		if tunnel.Enabled && (tunnel.Kind == TunnelWG || tunnel.Kind == TunnelWGReverse) &&
			tunnel.ListenerNode() == in.NodeID && tunnel.ListenPort == in.Port {
			add("инбаунд %s: UDP-порт %d на узле %s занят туннелем %s", in.Tag, in.Port, in.NodeID, tunnel.Name)
		}
	}
	listen, err := netip.ParseAddr(in.Listen)
	if err != nil {
		return // validateWireGuard reports an invalid listen address.
	}
	for _, other := range s.Inbounds[:index] {
		if !other.Enabled || other.Kind != InboundWireGuard || other.NodeID != in.NodeID || other.Port != in.Port {
			continue
		}
		addr, err := netip.ParseAddr(other.Listen)
		if err == nil && (addr.Unmap() == listen.Unmap() || addr.IsUnspecified() || listen.IsUnspecified()) {
			add("инбаунд %s: UDP-порт %d на узле %s занят инбаундом %s", in.Tag, in.Port, in.NodeID, other.Tag)
		}
	}
}
