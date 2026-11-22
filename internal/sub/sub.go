// Package sub собирает подписку клиента: список ссылок, которые клиент
// перезапрашивает по URL /sub/<token>.
package sub

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"revhub/internal/model"
)

// Links возвращает ссылки клиента. Пустой список — легальный ответ:
// клиент выключен, истёк или у него нет активных инбаундов.
func Links(st model.State, c model.Client) []string {
	if !c.Enabled || Expired(c) {
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
		if in.Kind == "vless" {
			out = append(out, vlessLink(in, node, host, port, c, st))
		}
	}
	return out
}

// Payload — то, что уходит по HTTP: base64 от списка ссылок через \n.
func Payload(links []string) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))
}

func Expired(c model.Client) bool {
	if c.ExpiresAt == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, c.ExpiresAt)
	if err != nil {
		return true
	}
	return time.Now().After(t)
}

func vlessLink(in model.Inbound, node model.Node, host string, port int, c model.Client, st model.State) string {
	q := url.Values{}
	q.Set("type", orDefault(in.Transport, "tcp"))
	q.Set("encryption", "none")
	q.Set("security", orDefault(in.Security, "none"))
	if in.SNI != "" {
		q.Set("sni", in.SNI)
	}
	if in.Security == "tls" {
		q.Set("fp", "chrome")
		// Самоподписанный сертификат не проверить по цепочке: клиенту либо
		// allowInsecure, либо пин (его печатает `revhub tls info`).
		if in.SelfSigned {
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
		q.Set("host", orDefault(in.SNI, host))
	}
	if flow := clientFlow(in, c); flow != "" {
		q.Set("flow", flow)
	}
	name := c.Email + "@" + in.Tag
	if node.Name != "" {
		name += " (" + node.Name + ")"
	}
	return fmt.Sprintf("vless://%s@%s:%d?%s#%s", c.UUID, host, port, q.Encode(), url.PathEscape(name))
}

func clientFlow(in model.Inbound, c model.Client) string {
	if c.Flow != "" {
		return c.Flow
	}
	return in.Flow
}

func hostPort(publicAddr string, fallbackPort int) (string, int) {
	if publicAddr == "" {
		return "127.0.0.1", fallbackPort
	}
	i := strings.LastIndex(publicAddr, ":")
	if i < 0 {
		return publicAddr, fallbackPort
	}
	if p, err := strconv.Atoi(publicAddr[i+1:]); err == nil && p > 0 {
		return publicAddr[:i], p
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
