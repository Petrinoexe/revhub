package sub

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"strconv"

	"revhub/internal/model"
)

// ThroneRouteLink возвращает отдельный профиль маршрутизации для явного
// импорта. Throne удаляет DNS-настройки из профилей, полученных с подпиской.
func ThroneRouteLink(st model.State, c model.Client) (string, error) {
	if !c.Enabled || c.Expired() || st.DNS == nil {
		return "", nil
	}
	nodeID := st.DNS.NodeID
	addr, port := st.InfraDNSAddress(nodeID)
	if addr == "" {
		return "", nil
	}

	// Вся группа использует один резолвер, доступный через инбаунды хаба.
	hasHubInbound := false
	for _, in := range st.Inbounds {
		if !in.Enabled || !hasID(c.Inbounds, in.ID) {
			continue
		}
		if in.NodeID != nodeID {
			return "", nil
		}
		hasHubInbound = true
	}
	if !hasHubInbound {
		return "", nil
	}

	profile := map[string]any{
		"kind":             "throne-route-profile",
		"v":                1,
		"name":             "RevHub · " + st.DNS.Root,
		"default_outbound": "proxy",
		"dns": map[string]any{
			"remote_dns":         "tcp://" + net.JoinHostPort(addr, strconv.Itoa(port)),
			"dns_final_out":      "remote",
			"enable_dns_routing": false,
			"fake_dns":           false,
		},
		// Явные CIDR оставляют частные сети внутри TUN в этом профиле.
		"rules": []any{map[string]any{
			"name":     "Весь трафик через прокси",
			"type":     "custom",
			"action":   "route",
			"outbound": "proxy",
			"ip_cidr":  []string{"0.0.0.0/0", "::/0"},
		}},
	}
	body, err := json.Marshal(profile)
	if err != nil {
		return "", err
	}
	return "throne://route/" + base64.RawURLEncoding.EncodeToString(body), nil
}
