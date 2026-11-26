package sub

import (
	"fmt"
	"strings"

	"revhub/internal/model"
)

// Config — готовый к скачиванию клиентский конфиг WireGuard (wg-quick).
// Текст уходит файлом как есть: wg-quick up <имя>.conf читает его без правок.
type Config struct {
	Inbound string `json:"inbound"`
	Tag     string `json:"tag"`
	File    string `json:"file"`
	Text    string `json:"text"`
}

// WireGuardConfigs собирает конфиги клиента: по одному на каждый включённый
// WireGuard-инбаунд, к которому он привязан. Пустой список — легальный ответ:
// клиент или инбаунд выключен, истёк срок либо нет адреса узла.
func WireGuardConfigs(st model.State, c model.Client) []Config {
	if !c.Enabled || c.Expired() {
		return nil
	}
	var out []Config
	for _, in := range st.Inbounds {
		if !in.Enabled || in.Kind != model.InboundWireGuard || in.WireGuard == nil || !hasID(c.Inbounds, in.ID) {
			continue
		}
		node, ok := nodeByID(st, in.NodeID)
		if !ok || node.PublicAddr == "" {
			continue
		}
		peer, ok := c.WireGuard[in.ID]
		if !ok || peer.PrivateKey == "" || peer.Address == "" {
			continue
		}
		out = append(out, Config{
			Inbound: in.ID,
			Tag:     in.Tag,
			File:    fileName(c, in.Tag),
			Text:    wgConfigText(st, c, in, node, peer),
		})
	}
	return out
}

// wireGuardDNS — один резолвер и для wireguard://, и для скачанного .conf.
func wireGuardDNS(st model.State, in model.Inbound) string {
	if st.DNS != nil && st.DNS.Enabled() && st.DNS.NodeID == in.NodeID &&
		st.Infra != nil && st.Infra.Enabled && st.Infra.NodeID == in.NodeID {
		if addr := st.Infra.ServerAddress(); addr != "" {
			return addr
		}
	}
	// DNS зоны пока нет: отдаём один внешний резолвер. Список через запятую
	// часть клиентов парсит как одно (невалидное) имя.
	if i := strings.IndexByte(in.WireGuard.DNS, ','); i >= 0 {
		return strings.TrimSpace(in.WireGuard.DNS[:i])
	}
	return strings.TrimSpace(in.WireGuard.DNS)
}

// wgConfigText — стандартный формат wg-quick: клиент дозванивается до узла,
// серверный адрес берётся из инбаунда, ключи — из пары клиента. Весь трафик
// (0.0.0.0/0) уходит в туннель, keepalive держит NAT-сессию живой.
func wgConfigText(st model.State, c model.Client, in model.Inbound, node model.Node, peer model.WireGuardPeer) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# revhub: %s · %s\n", c.Email, in.Tag)
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", peer.PrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", peer.Address)
	// Зона DNS живёт на адресе интерфейса (dnsmasq слушает 10.88.0.1).
	dns := wireGuardDNS(st, in)
	if dns != "" {
		fmt.Fprintf(&b, "DNS = %s\n", dns)
	}
	fmt.Fprintf(&b, "MTU = %d\n", model.DefaultWireGuardMTU)
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", in.WireGuard.PublicKey)
	if peer.PresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", peer.PresharedKey)
	}
	b.WriteString("AllowedIPs = 0.0.0.0/0\n")
	fmt.Fprintf(&b, "Endpoint = %s\n", wgEndpoint(in, node))
	b.WriteString("PersistentKeepalive = 25\n")
	return b.String()
}

// fileName — имя файла для скачивания: только ASCII, иначе часть клиентов
// (Windows, Android) сохраняет файл с мусором в имени.
func fileName(c model.Client, tag string) string {
	stem := slug(c.Email)
	if t := slug(tag); t != "" {
		if stem != "" {
			stem += "-"
		}
		stem += t
	}
	if stem == "" {
		stem = "client"
	}
	return stem + ".conf"
}

func slug(s string) string {
	var b strings.Builder
	dashed := false
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' {
			b.WriteRune(r)
			dashed = false
			continue
		}
		if !dashed && b.Len() > 0 {
			b.WriteByte('-')
			dashed = true
		}
	}
	return strings.Trim(b.String(), "-")
}
