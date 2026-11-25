// Package sub собирает подписку клиента: список ссылок, которые клиент
// перезапрашивает по URL /sub/<token>.
package sub

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"revhub/internal/model"
)

// Links возвращает ссылки клиента. Пустой список — легальный ответ:
// клиент выключен, истёк или у него нет активных инбаундов.
func Links(st model.State, c model.Client) []string {
	if !c.Enabled || c.Expired() {
		return nil
	}
	var out []string
	for _, in := range st.Inbounds {
		if !in.Enabled || !hasID(c.Inbounds, in.ID) {
			continue
		}
		node, ok := nodeByID(st, in.NodeID)
		if !ok {
			continue
		}
		host, port := hostPort(node.PublicAddr, in.Port)
		switch in.Kind {
		case model.InboundVLESS, "":
			if in.Security == "tls" && in.CertSource == "panel" {
				port = in.Port
			}
			out = append(out, vlessLink(in, node, host, port, c, st))
		case model.InboundWireGuard:
			peer, ok := c.WireGuard[in.ID]
			if ok && in.WireGuard != nil && node.PublicAddr != "" {
				out = append(out, wireGuardLink(in, wgEndpoint(in, node), c, peer, wireGuardDNS(st, in)))
			}
		}
	}
	return out
}

// Payload — то, что уходит по HTTP: base64 от списка ссылок через \n.
func Payload(links []string) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))
}

// wireguard:// соответствует формату импорта v2rayN.
func wireGuardLink(in model.Inbound, endpoint string, c model.Client, peer model.WireGuardPeer, dns string) string {
	q := url.Values{
		"publickey": {in.WireGuard.PublicKey}, "presharedkey": {peer.PresharedKey},
		"address": {peer.Address}, "mtu": {strconv.Itoa(model.DefaultWireGuardMTU)},
	}
	// DNS совпадает с wg-quick конфигом, включая внутреннюю зону dnsmasq.
	if strings.TrimSpace(dns) != "" {
		q.Set("dns", dns)
	}
	u := url.URL{
		Host: endpoint, RawQuery: q.Encode(),
		Fragment: c.Email + "@" + in.Tag,
	}
	// v2rayN декодирует userinfo как query, поэтому '+' в base64 экранируем явно.
	return "wireguard://" + url.QueryEscape(peer.PrivateKey) + "@" + strings.TrimPrefix(u.String(), "//")
}

// wgEndpoint — host:port, который клиент дозванивает для WireGuard-инбаунда.
// Порт берётся у инбаунда: в public_addr обычно порт панели или TCP-инбаунда,
// поэтому из него нужен только хост.
func wgEndpoint(in model.Inbound, node model.Node) string {
	host, _ := hostPort(node.PublicAddr, in.Port)
	return net.JoinHostPort(host, strconv.Itoa(in.Port))
}

func vlessLink(in model.Inbound, node model.Node, host string, port int, c model.Client, st model.State) string {
	q := url.Values{}
	q.Set("type", orDefault(in.Transport, "tcp"))
	q.Set("encryption", "none")
	q.Set("security", orDefault(in.Security, "none"))
	sni := in.EffectiveSNI()
	if sni != "" {
		q.Set("sni", sni)
	}
	if in.Security == "tls" {
		q.Set("fp", "chrome")
		// Самоподписанный сертификат не проверить по цепочке: клиенту либо
		// allowInsecure, либо пин (его печатает `revhub tls info`).
		if in.CertSource == "panel" && in.CertSHA256 != "" {
			q.Set("pcs", in.CertSHA256)
		} else if in.SelfSigned || in.CertSource == "selfsigned" {
			q.Set("allowInsecure", "1")
		}
	}
	if in.Security == "reality" {
		q.Set("pbk", in.PublicKey)
		q.Set("sid", in.ShortID)
		q.Set("fp", "chrome")
	}
	if in.Path != "" {
		q.Set("path", in.Path)
	}
	if in.Transport == "ws" || in.Transport == "xhttp" {
		q.Set("host", orDefault(sni, host))
	}
	if flow := in.ClientFlow(c); flow != "" {
		q.Set("flow", flow)
	}
	name := c.Email + "@" + in.Tag
	if node.Name != "" {
		name += " (" + node.Name + ")"
	}
	return fmt.Sprintf("vless://%s@%s?%s#%s", c.UUID, net.JoinHostPort(host, strconv.Itoa(port)), q.Encode(), url.PathEscape(name))
}

func hostPort(publicAddr string, fallbackPort int) (string, int) {
	if publicAddr == "" {
		return "127.0.0.1", fallbackPort
	}
	if host, port, err := net.SplitHostPort(publicAddr); err == nil {
		if p, err := strconv.Atoi(port); err == nil && p > 0 && p <= 65535 {
			return host, p
		}
		return host, fallbackPort
	}
	if addr, err := netip.ParseAddr(strings.Trim(publicAddr, "[]")); err == nil {
		return addr.String(), fallbackPort
	}
	return publicAddr, fallbackPort
}

func nodeByID(st model.State, id string) (model.Node, bool) {
	for _, n := range st.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return model.Node{}, false
}

func hasID(list []string, id string) bool {
	for _, s := range list {
		if s == id {
			return true
		}
	}
	return false
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
