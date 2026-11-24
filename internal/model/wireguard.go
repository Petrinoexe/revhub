package model

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
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
