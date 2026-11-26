package sub

import (
	"encoding/json"
	"fmt"

	"revhub/internal/model"
)

// SingBoxJSON рендерит готовый sing-box конфиг для клиентов вроде Throne:
// интернет и сеть внутри одного профиля, без ручной настройки DNS.
//
// wireguard:// ссылка переносит только ключи и endpoint — DNS и маршруты
// клиент не получает. Поэтому внутренняя зона и выход в интернет описаны
// здесь явно: DNS-правило domain_suffix → dnsmasq хаба, весь остальной
// трафик — через туннель.
//
// Формат DNS — sing-box 1.11+ (type/server): Throne отслеживает ядро
// sing-box, а legacy-поля address из 1.10 удалены в 1.12.
func SingBoxJSON(st model.State, c model.Client) ([]byte, bool, error) {
	if !c.Enabled || c.Expired() {
		return nil, false, nil
	}
	var in model.Inbound
	var node model.Node
	var peer model.WireGuardPeer
	found := false
	for _, cand := range st.Inbounds {
		if !cand.Enabled || cand.Kind != model.InboundWireGuard || cand.WireGuard == nil || !hasID(c.Inbounds, cand.ID) {
			continue
		}
		n, ok := nodeByID(st, cand.NodeID)
		if !ok || n.PublicAddr == "" {
			continue
		}
		p, ok := c.WireGuard[cand.ID]
		if !ok || p.PrivateKey == "" || p.Address == "" {
			continue
		}
		in, node, peer, found = cand, n, p, true
		break
	}
	if !found {
		return nil, false, nil
	}

	dnsServers := []map[string]any{}
	var dnsRules []map[string]any
	if st.DNS != nil && st.DNS.Enabled() && st.DNS.NodeID == in.NodeID &&
		st.Infra != nil && st.Infra.Enabled && st.Infra.NodeID == in.NodeID {
		if addr := st.Infra.ServerAddress(); addr != "" {
			dnsServers = append(dnsServers, map[string]any{
				"tag": "infra", "type": "udp", "server": addr, "detour": "wg-out",
			})
			dnsRules = append(dnsRules, map[string]any{
				"domain_suffix": []string{"." + st.DNS.Root}, "server": "infra",
			})
		}
	}
	// Внешние имена — тоже через туннель: иначе при выходе через туннель
	// резолвер «выезжает» из другой страны, чем сам трафик.
	dnsServers = append(dnsServers, map[string]any{
		"tag": "default", "type": "udp", "server": "1.1.1.1", "detour": "wg-out",
	})

	wireguard := map[string]any{
		"type":            "wireguard",
		"tag":             "wg-out",
		"server":          hostOnlyOf(wgEndpoint(in, node)),
		"server_port":     in.Port,
		"local_address":   []string{peer.Address},
		"private_key":     peer.PrivateKey,
		"peer_public_key": in.WireGuard.PublicKey,
		"mtu":             model.DefaultWireGuardMTU,
	}
	if peer.PresharedKey != "" {
		wireguard["pre_shared_key"] = peer.PresharedKey
	}

	cfg := map[string]any{
		"log": map[string]any{"level": "warn"},
		"dns": map[string]any{
			"servers": dnsServers,
			"rules":   dnsRules,
			"final":   "default",
		},
		"outbounds": []any{
			wireguard,
			map[string]any{"type": "direct", "tag": "direct"},
		},
		"route": map[string]any{
			"final":                 "wg-out",
			"auto_detect_interface": true,
		},
	}
	if dnsRules == nil {
		// Без зоны DNS rules не нужен вовсе: sing-box ругается на null.
		delete(cfg["dns"].(map[string]any), "rules")
	}
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, false, fmt.Errorf("sing-box конфиг: %w", err)
	}
	return append(out, '\n'), true, nil
}

func hostOnlyOf(hostport string) string {
	for i := len(hostport) - 1; i >= 0; i-- {
		if hostport[i] == ':' {
			return hostport[:i]
		}
	}
	return hostport
}
