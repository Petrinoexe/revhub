package gen

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"revhub/internal/model"
)

// InfraWGConf рендерит серверный конфиг инфраструктурной сети (wg-infra) на
// узле-хабе. В отличие от клиентских инбаундов это полноценная L3-сеть:
// пиры видят друг друга напрямую (все /32 в одном интерфейсе), им разрешён
// forward и ICMP, а наружу они выходят через общий egress сети или личный
// egress пира — тем же механизмом fwmark/таблиц, что и клиенты.
func InfraWGConf(st model.State, nodeID string) (string, bool, error) {
	ic := st.Infra
	if ic == nil || !ic.Enabled || ic.NodeID != nodeID {
		return "", false, nil
	}
	if ic.PrivateKey == "" || ic.PublicKey == "" {
		return "", false, fmt.Errorf("инфра: нет ключей сервера")
	}
	if pub := wgPublicKeyOf(ic.PrivateKey); pub == "" || pub != ic.PublicKey {
		return "", false, fmt.Errorf("инфра: неверная пара ключей сервера")
	}
	if ic.ListenPort <= 0 || ic.ListenPort > 65535 {
		return "", false, fmt.Errorf("инфра: некорректный порт %d", ic.ListenPort)
	}
	server := ic.ServerAddress()
	if server == "" {
		return "", false, fmt.Errorf("инфра: некорректная подсеть %q", ic.Subnet)
	}
	pfx, err := netip.ParsePrefix(ic.Subnet)
	if err != nil {
		return "", false, fmt.Errorf("инфра: некорректная подсеть %q", ic.Subnet)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# revhub: инфраструктурная сеть %q на узле %s\n", ic.Interface, nodeID)
	fmt.Fprintf(&b, "# сеть %s: пиры видят друг друга, выход — %s\n", ic.Subnet, infraEgressText(st, ic.Egress))
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "Address = %s/%d\n", server, pfx.Bits())
	fmt.Fprintf(&b, "PrivateKey = %s\n", ic.PrivateKey)
	fmt.Fprintf(&b, "ListenPort = %d\n", ic.ListenPort)
	fmt.Fprintf(&b, "MTU = %d\n", model.DefaultWireGuardMTU)

	// Пиры общаются между собой через этот интерфейс — это forwarding.
	b.WriteString("PostUp = " + soft("sysctl -q -w net.ipv4.ip_forward=1",
		"ip_forward не включился — инфра-пиры не увидят друг друга") + "\n")
	b.WriteString("PostUp = " + soft("printf '2\\n' > /proc/sys/net/ipv4/conf/%i/rp_filter",
		"rp_filter не сброшен в loose — часть пакетов может фильтроваться") + "\n")
	b.WriteString("PostUp = " + soft("iptables -I FORWARD -i %i -j ACCEPT",
		"правило FORWARD не добавилось — инфра-пиры не пройдут при политике drop") + "\n")
	b.WriteString("PostUp = " + soft("iptables -I FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
		"правило FORWARD для обратного трафика не добавилось") + "\n")
	b.WriteString("PostDown = iptables -D FORWARD -i %i -j ACCEPT 2>/dev/null || true\n")
	b.WriteString("PostDown = iptables -D FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true\n")

	// Доступ пользовательских VPN-клиентов к инфраструктуре: их трафик приходит
	// на клиентский WG-интерфейс, а уходит в wg-infra — это forward между двумя
	// разными интерфейсами, и политика FORWARD=DROP его иначе съест. Правила
	// симметричные: клиент→сервис и сервис→клиент (например, ping из инфры).
	for _, in := range st.Inbounds {
		if !in.Enabled || in.Kind != model.InboundWireGuard || in.NodeID != nodeID ||
			in.WireGuard == nil || in.WireGuard.Subnet == "" {
			continue
		}
		subnet := in.WireGuard.Subnet
		fmt.Fprintf(&b, "PostUp = iptables -I FORWARD -s %s -o %%i -j ACCEPT\n", subnet)
		fmt.Fprintf(&b, "PostUp = iptables -I FORWARD -d %s -i %%i -j ACCEPT\n", subnet)
		fmt.Fprintf(&b, "PostDown = iptables -D FORWARD -s %s -o %%i -j ACCEPT 2>/dev/null || true\n", subnet)
		fmt.Fprintf(&b, "PostDown = iptables -D FORWARD -d %s -i %%i -j ACCEPT 2>/dev/null || true\n", subnet)
	}

	// Маршрут на всю инфра-подсеть через интерфейс: адреса пиров попали в
	// AllowedIPs /32, но маршрут на сеть нужен, чтобы трафик к любому
	// свободному адресу не уходил в default.
	fmt.Fprintf(&b, "PostUp = ip -4 route replace %s dev %%i\n", ic.Subnet)
	fmt.Fprintf(&b, "PostDown = ip -4 route del %s dev %%i 2>/dev/null || true\n", ic.Subnet)

	// Трафик между пирами всегда использует main, даже если личный
	// выход пира назначен на другую таблицу или туннель перезапущен.
	fmt.Fprintf(&b, "PostUp = ip -4 rule add iif %%i to %s lookup main pref 31899\n", ic.Subnet)
	fmt.Fprintf(&b, "PostDown = ip -4 rule del iif %%i to %s lookup main pref 31899 2>/dev/null || true\n", ic.Subnet)

	table := nftTable(ic.Interface)
	natTunnels := map[int]bool{}
	directOverride := false
	switch {
	case strings.HasPrefix(ic.Egress, model.TagTunnel):
		name := strings.TrimPrefix(ic.Egress, model.TagTunnel)
		t, ok := findTunnel(st, name)
		if !ok || t.FromNode != nodeID {
			return "", false, fmt.Errorf("инфра: нет включённого туннеля %s на узле %s", name, nodeID)
		}
		fmt.Fprintf(&b, "PostUp = ip -4 rule add iif %%i lookup %d pref 32000\n", t.Mark)
		b.WriteString("PostUp = ip -4 rule add unreachable iif %i pref 32001\n")
		fmt.Fprintf(&b, "PostDown = ip -4 rule del iif %%i lookup %d pref 32000 2>/dev/null || true\n", t.Mark)
		b.WriteString("PostDown = ip -4 rule del unreachable iif %i pref 32001 2>/dev/null || true\n")
		writeTunnelNAT(&b, ic.Subnet, table, t.WGInterface())
		natTunnels[t.Mark] = true
	default:
		rules := []string{
			fmt.Sprintf(`add table ip %s`, table),
			fmt.Sprintf(`add chain ip %s postrouting { type nat hook postrouting priority 100; }`, table),
			fmt.Sprintf(`add rule ip %s postrouting iifname "%%i" oifname != "%%i" masquerade`, table),
		}
		b.WriteString("PostUp = " + soft("if command -v nft >/dev/null; then "+printfNewline+shellJoin(rules)+
			" | nft -f -; else iptables -t nat -I POSTROUTING -s "+ic.Subnet+" ! -o %i -j MASQUERADE; fi",
			"не удалось включить NAT инфра-сети — выхода в интернет не будет") + "\n")
		b.WriteString("PostDown = if command -v nft >/dev/null; then nft delete table ip " + table +
			" 2>/dev/null || true; else iptables -t nat -D POSTROUTING -s " + ic.Subnet +
			" ! -o %i -j MASQUERADE 2>/dev/null || true; fi\n")
		directOverride = true
	}

	// Личные выходы пиров: правило по адресу источника выше общего (31900).
	for _, pr := range st.InfraPeers {
		if !pr.Enabled || pr.Egress == "" || pr.Address == "" {
			continue
		}
		ip := strings.TrimSuffix(pr.Address, "/32")
		bucket := "main"
		if strings.HasPrefix(pr.Egress, model.TagTunnel) {
			name := strings.TrimPrefix(pr.Egress, model.TagTunnel)
			t, ok := findTunnel(st, name)
			if !ok || t.FromNode != nodeID {
				return "", false, fmt.Errorf("инфра-пир %s: нет включённого туннеля %s на узле %s", pr.Name, name, nodeID)
			}
			bucket = strconv.Itoa(t.Mark)
			if !natTunnels[t.Mark] {
				natTunnels[t.Mark] = true
				writeTunnelNAT(&b, ic.Subnet, table, t.WGInterface())
			}
		} else if pr.Egress == model.TagDirect {
			if !directOverride {
				directOverride = true
				writeDirectNAT(&b, ic.Subnet, table+"_d")
			}
		} else {
			continue
		}
		fmt.Fprintf(&b, "PostUp = ip rule add from %s/32 lookup %s pref 31900\n", ip, bucket)
		fmt.Fprintf(&b, "PostDown = ip rule del from %s/32 lookup %s pref 31900 2>/dev/null || true\n", ip, bucket)
		if bucket != "main" {
			fmt.Fprintf(&b, "PostUp = ip -4 rule add unreachable iif %%i from %s/32 pref 31901\n", ip)
			fmt.Fprintf(&b, "PostDown = ip -4 rule del unreachable iif %%i from %s/32 pref 31901 2>/dev/null || true\n", ip)
		}
	}

	peers := 0
	for _, pr := range st.InfraPeers {
		if !pr.Enabled {
			continue
		}
		for _, key := range []string{pr.PublicKey, pr.PresharedKey} {
			if raw, err := base64.StdEncoding.DecodeString(key); err != nil || len(raw) != 32 {
				return "", false, fmt.Errorf("инфра-пир %s: некорректный ключ WireGuard", infraPeerName(pr))
			}
		}
		if _, ok := modelPeerPrefix(pr.Address); !ok {
			return "", false, fmt.Errorf("инфра-пир %s: некорректный адрес %q", infraPeerName(pr), pr.Address)
		}
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(&b, "# %s\n", infraPeerName(pr))
		fmt.Fprintf(&b, "PublicKey = %s\n", pr.PublicKey)
		fmt.Fprintf(&b, "PresharedKey = %s\n", pr.PresharedKey)
		fmt.Fprintf(&b, "AllowedIPs = %s\n", pr.Address)
		peers++
	}
	if peers == 0 {
		b.WriteString("\n# пиров пока нет: инфра-сеть поднимется пустой\n")
	}
	return b.String(), true, nil
}

// InfraPeerConfig — wg-quick конфиг самой инфра-машины. Весь трафик пира идёт
// через хаб (AllowedIPs 0.0.0.0/0): так он одновременно получает интернет
// через общий выход и доступ к остальным инфра-пирам.
func InfraPeerConfig(st model.State, peer model.InfraPeer) (string, bool, error) {
	ic := st.Infra
	if ic == nil || !ic.Enabled || !peer.Enabled {
		return "", false, nil
	}
	if peer.PrivateKey == "" || peer.PublicKey == "" || peer.Address == "" {
		return "", false, fmt.Errorf("инфра-пир %s: нет ключей или адреса", infraPeerName(peer))
	}
	var node model.Node
	for _, n := range st.Nodes {
		if n.ID == ic.NodeID {
			node = n
		}
	}
	if node.PublicAddr == "" {
		return "", false, fmt.Errorf("инфра: у узла %s нет public_addr", ic.NodeID)
	}
	host := hostOnly(node.PublicAddr)
	endpoint := hostPortJoin(host, ic.ListenPort)

	var b strings.Builder
	fmt.Fprintf(&b, "# revhub: инфраструктурный пир %s\n", infraPeerName(peer))
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", peer.PrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", peer.Address)
	fmt.Fprintf(&b, "MTU = %d\n", model.DefaultWireGuardMTU)
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", ic.PublicKey)
	if peer.PresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", peer.PresharedKey)
	}
	b.WriteString("AllowedIPs = 0.0.0.0/0\n")
	fmt.Fprintf(&b, "Endpoint = %s\n", endpoint)
	b.WriteString("PersistentKeepalive = 25\n")
	return b.String(), true, nil
}

func infraEgressText(st model.State, egress string) string {
	if name, ok := strings.CutPrefix(egress, model.TagTunnel); ok {
		return "в туннель " + name
	}
	return "NAT этого узла"
}

func hostPortJoin(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func infraPeerName(p model.InfraPeer) string {
	if p.Name != "" {
		return p.Name
	}
	return p.ID
}
