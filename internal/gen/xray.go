// Package gen рендерит артефакты узла: конфиг xray и интерфейсы WireGuard.
// Живой конфиг всегда производный от model.State; обратной записи нет.
package gen

import (
	"encoding/json"
	"fmt"
	"strings"

	"revhub/internal/model"
)

const apiTag = "api"

// XrayConfig собирает конфиг xray для одного узла.
func XrayConfig(st model.State, nodeID string) (map[string]any, error) {
	if _, ok := findNode(st, nodeID); !ok {
		return nil, fmt.Errorf("узел %q не найден", nodeID)
	}

	inbounds := []any{apiInbound()}
	var tunnelInbounds []any

	for _, in := range st.Inbounds {
		if in.NodeID != nodeID || !in.Enabled {
			continue
		}
		if in.Kind == model.InboundWireGuard {
			// Пользовательский WireGuard — userspace-inbound Xray (как в 3x-ui):
			// TCP/UDP идут через routing, ядерного интерфейса нет.
			ib, err := buildWireGuardInbound(st, in)
			if err != nil {
				return nil, fmt.Errorf("инбаунд %s: %w", in.Tag, err)
			}
			inbounds = append(inbounds, ib)
			continue
		}
		ib, err := buildInbound(st, in)
		if err != nil {
			return nil, fmt.Errorf("инбаунд %s: %w", in.Tag, err)
		}
		inbounds = append(inbounds, ib)
	}

	outbounds := []any{
		map[string]any{"protocol": "freedom", "tag": model.TagDirect},
		map[string]any{"protocol": "blackhole", "tag": model.TagBlock},
	}
	dnsAddress, dnsPort := st.InfraDNSAddress(nodeID)
	if subnet := st.InfraSubnet(nodeID); subnet != "" {
		// Freedom проверяет назначение после выбора маршрута и по умолчанию
		// блокирует частные адреса у входящих VLESS и WireGuard.
		infra := map[string]any{
			"protocol": "freedom", "tag": model.TagInfra,
			"settings": map[string]any{"finalRules": []any{
				map[string]any{"action": "allow", "ip": []string{subnet}},
			}},
		}
		if dnsAddress != "" {
			infra["streamSettings"] = map[string]any{
				"sockopt": map[string]any{"domainStrategy": "ForceIPv4"},
			}
		}
		outbounds = append(outbounds, infra)
	}
	if dnsAddress != "" {
		outbounds = append(outbounds, map[string]any{
			"protocol": "freedom", "tag": model.TagInfraDNS,
			"settings": map[string]any{
				"redirect": hostPortJoin(dnsAddress, dnsPort),
				"finalRules": []any{map[string]any{
					"action": "allow", "ip": []string{dnsAddress}, "port": dnsPort, "network": "tcp,udp",
				}},
			},
		})
	}

	for _, t := range st.Tunnels {
		if !t.Enabled || !t.Touches(nodeID) {
			continue
		}
		switch t.Kind {
		case model.TunnelVLESS:
			if t.FromNode == nodeID {
				ob, err := buildVlessOutbound(st, t)
				if err != nil {
					return nil, fmt.Errorf("туннель %s: %w", t.Name, err)
				}
				outbounds = append(outbounds, ob)
			} else {
				ib, err := buildVlessTunnelInbound(t)
				if err != nil {
					return nil, fmt.Errorf("туннель %s: %w", t.Name, err)
				}
				tunnelInbounds = append(tunnelInbounds, ib)
			}
		case model.TunnelWG, model.TunnelWGReverse:
			if t.FromNode == nodeID {
				// Трафик этого узла уходит в ядерный интерфейс по метке.
				outbounds = append(outbounds, map[string]any{
					"protocol": "freedom",
					"tag":      t.Tag(),
					"streamSettings": map[string]any{
						"sockopt": map[string]any{"mark": t.Mark},
					},
				})
			}
		}
	}
	inbounds = append(inbounds, tunnelInbounds...)

	rules, err := buildRules(st, nodeID)
	if err != nil {
		return nil, err
	}

	cfg := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"api": map[string]any{
			"tag":      apiTag,
			"services": []string{"HandlerService", "LoggerService", "StatsService", "RoutingService"},
		},
		"stats": map[string]any{},
		"policy": map[string]any{"system": map[string]any{
			"statsInboundUplink": true, "statsInboundDownlink": true,
			"statsOutboundUplink": true, "statsOutboundDownlink": true,
		}},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing":   map[string]any{"domainStrategy": "AsIs", "rules": rules},
	}
	if dnsAddress != "" {
		cfg["dns"] = map[string]any{
			"servers": []string{"tcp+local://" + hostPortJoin(dnsAddress, dnsPort)},
		}
	}

	return cfg, nil
}

// XrayJSON — то же, но сериализованное.
func XrayJSON(st model.State, nodeID string) ([]byte, error) {
	cfg, err := XrayConfig(st, nodeID)
	if err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func apiInbound() map[string]any {
	return map[string]any{
		"tag":      apiTag,
		"listen":   "127.0.0.1",
		"port":     62789,
		"protocol": "dokodemo-door",
		"settings": map[string]any{"address": "127.0.0.1"},
	}
}

func buildInbound(st model.State, in model.Inbound) (map[string]any, error) {
	clients := []any{}
	for _, c := range st.Clients {
		if !c.Enabled || c.Expired() || !contains(c.Inbounds, in.ID) {
			continue
		}
		cl := map[string]any{"id": c.UUID, "email": c.Email}
		if flow := in.ClientFlow(c); flow != "" {
			cl["flow"] = flow
		}
		clients = append(clients, cl)
	}
	settings := map[string]any{
		"clients":    clients,
		"decryption": "none",
	}

	sni, cert, key := in.SNI, in.CertFile, in.KeyFile
	if in.Security == "tls" {
		_, cert, key = tlsResolve(in.CertSource, in.Domain, in.IP, in.CertFile, in.KeyFile)
		sni = in.EffectiveSNI()
	}
	stream, err := streamSettings(streamOpts{
		Transport: in.Transport, Security: in.Security, SNI: sni, Dest: in.Dest,
		Path: in.Path, PrivateKey: in.PrivateKey, ShortID: in.ShortID,
		CertFile: cert, KeyFile: key,
	})
	if err != nil {
		return nil, err
	}
	sniffing := map[string]any{
		"enabled":      true,
		"destOverride": []string{"http", "tls", "quic"},
	}
	if subnet := st.InfraSubnet(in.NodeID); subnet != "" {
		// HTTP Host и TLS SNI не должны заменять IP инфраструктуры.
		sniffing["ipsExcluded"] = []string{subnet}
	}
	return map[string]any{
		"tag":            in.Tag,
		"listen":         in.Listen,
		"port":           in.Port,
		"protocol":       "vless",
		"settings":       settings,
		"streamSettings": stream,
		"sniffing":       sniffing,
	}, nil
}

// buildWireGuardInbound — пользовательский WireGuard внутри Xray-core
// (userspace). Формат повторяет 3x-ui и документацию Xray: в settings только
// secretKey, peers и mtu. Поля address у inbound нет — адреса клиентов задаются
// их allowedIPs, а стек Xray сам превращает пакеты в TCP/UDP-потоки, которые
// идут через routing (infra-outbound, tun-метки, direct).
func buildWireGuardInbound(st model.State, in model.Inbound) (map[string]any, error) {
	wg := in.WireGuard
	if wg == nil || wg.PrivateKey == "" || wg.PublicKey == "" {
		return nil, fmt.Errorf("нет ключей WireGuard")
	}
	if pub := wgPublicKeyOf(wg.PrivateKey); pub == "" || pub != wg.PublicKey {
		return nil, fmt.Errorf("неверная пара ключей WireGuard")
	}
	if in.Port <= 0 || in.Port > 65535 {
		return nil, fmt.Errorf("некорректный порт %d", in.Port)
	}
	peers := []any{}
	for _, c := range st.Clients {
		if !c.Enabled || c.Expired() || !contains(c.Inbounds, in.ID) {
			continue
		}
		peer, ok := c.WireGuard[in.ID]
		if !ok || peer.Address == "" || peer.PublicKey == "" {
			return nil, fmt.Errorf("у клиента %s нет ключей WireGuard", c.Email)
		}
		if _, ok := modelPeerPrefix(peer.Address); !ok {
			return nil, fmt.Errorf("у клиента %s некорректный адрес WireGuard", c.Email)
		}
		p := map[string]any{
			"publicKey":  peer.PublicKey,
			"allowedIPs": []string{peer.Address},
			"email":      c.Email,
			"level":      0,
		}
		if peer.PresharedKey != "" {
			p["preSharedKey"] = peer.PresharedKey
		}
		peers = append(peers, p)
	}
	settings := map[string]any{
		"secretKey": wg.PrivateKey,
		"peers":     peers,
		"mtu":       model.DefaultWireGuardMTU,
	}
	return map[string]any{
		"tag":      in.Tag,
		"listen":   in.Listen,
		"port":     in.Port,
		"protocol": "wireguard",
		"settings": settings,
	}, nil
}

// buildVlessTunnelInbound — приёмная сторона туннеля kind=vless.
func buildVlessTunnelInbound(t model.Tunnel) (map[string]any, error) {
	if t.Security == "reality" && t.PrivateKey == "" {
		return nil, fmt.Errorf("для приёмной стороны reality нужен private_key")
	}
	sni, cert, key := t.SNI, t.CertFile, t.KeyFile
	if t.Security == "tls" {
		sni, cert, key = tlsResolve(t.CertSource, t.Domain, t.IP, t.CertFile, t.KeyFile)
	}
	stream, err := streamSettings(streamOpts{
		Transport: t.Transport, Security: t.Security, SNI: sni, Dest: t.Dest,
		Path: t.Path, PrivateKey: t.PrivateKey, ShortID: t.ShortID,
		CertFile: cert, KeyFile: key,
	})
	if err != nil {
		return nil, err
	}
	client := map[string]any{"id": t.UUID, "email": "tunnel:" + t.Name}
	if flow := model.EffectiveFlow(t.Flow, t.Transport, t.Security); flow != "" {
		client["flow"] = flow
	}
	return map[string]any{
		"tag":            t.Tag(),
		"listen":         "0.0.0.0",
		"port":           t.ListenPortT,
		"protocol":       "vless",
		"settings":       map[string]any{"clients": []any{client}, "decryption": "none"},
		"streamSettings": stream,
	}, nil
}

func buildVlessOutbound(st model.State, t model.Tunnel) (map[string]any, error) {
	to, ok := findNode(st, t.ToNode)
	if !ok {
		return nil, fmt.Errorf("узел назначения %q не найден", t.ToNode)
	}
	addr, port := splitAddr(to.PublicAddr, t.ListenPortT)
	obSNI := t.SNI
	if t.Security == "tls" {
		if t.Domain != "" {
			obSNI = t.Domain
		} else if t.IP != "" {
			obSNI = t.IP
		}
	}
	stream, err := streamSettings(streamOpts{
		Transport: t.Transport, Security: t.Security, SNI: obSNI, Path: t.Path,
		PublicKey: t.PublicKey, ShortID: t.ShortID, Pin: t.Pin,
	})
	if err != nil {
		return nil, err
	}
	settings := map[string]any{
		"address":    addr,
		"port":       port,
		"id":         t.UUID,
		"encryption": "none",
	}
	if flow := model.EffectiveFlow(t.Flow, t.Transport, t.Security); flow != "" {
		settings["flow"] = flow
	}
	return map[string]any{
		"protocol":       "vless",
		"tag":            t.Tag(),
		"settings":       settings,
		"streamSettings": stream,
	}, nil
}

// tlsResolve переводит «источник сертификата» в то, что нужно ядру: SNI и пути
// к файлам. Пути фиксированы: по ним панель кладёт сертификат на узел.
func tlsResolve(source, domain, ip, certFile, keyFile string) (sni, cert, key string) {
	switch source {
	case "acme":
		sni = domain
		cert, key = "/etc/revhub/tls/fullchain.pem", "/etc/revhub/tls/key.pem"
	case "acmeip":
		// отдельный каталог: на одном узле могут жить и доменный, и IP-сертификат
		sni = ip
		cert, key = "/etc/revhub/tls/ip/fullchain.pem", "/etc/revhub/tls/ip/key.pem"
	case "selfsigned":
		sni = ip
		if sni == "" {
			sni = domain
		}
		cert, key = "/etc/revhub/tls/server.crt", "/etc/revhub/tls/server.key"
	case "file":
		sni = domain
		if sni == "" {
			sni = ip
		}
		cert, key = certFile, keyFile
	}
	if sni == "" {
		sni = domain
	}
	if sni == "" {
		sni = ip
	}
	// Явно заданные пути сильнее умолчаний по источнику: так установщик в
	// песочнице и тесты работают с реально существующими файлами.
	if certFile != "" && keyFile != "" {
		cert, key = certFile, keyFile
	}
	return sni, cert, key
}

// streamOpts — общий набор полей транспорта для инбаунда и для клиентской
// стороны туннеля. Различие только в ключах: на приёме private, на отправке
// public; на отправке при security=tls может быть пин сертификата.
type streamOpts struct {
	Transport, Security, SNI, Dest, Path string
	PrivateKey, ShortID, PublicKey       string
	CertFile, KeyFile, Pin               string
}

func streamSettings(o streamOpts) (map[string]any, error) {
	transport, security := o.Transport, o.Security
	if transport == "" {
		transport = "tcp"
	}
	if security == "" {
		security = "none"
	}
	ss := map[string]any{"network": transport, "security": security}

	switch transport {
	case "tcp":
	case "ws":
		ss["wsSettings"] = map[string]any{"path": o.Path, "host": o.SNI}
	case "xhttp":
		ss["xhttpSettings"] = map[string]any{"path": o.Path, "mode": "auto"}
	default:
		return nil, fmt.Errorf("неизвестный транспорт %q", transport)
	}

	switch security {
	case "none":
	case "tls":
		tls := map[string]any{}
		if o.SNI != "" {
			tls["serverName"] = o.SNI
		}
		if o.CertFile != "" && o.KeyFile != "" {
			tls["certificates"] = []any{map[string]any{
				"certificateFile": o.CertFile,
				"keyFile":         o.KeyFile,
			}}
		}
		if o.Pin != "" {
			tls["pinnedPeerCertificateChainSha256"] = []string{o.Pin}
		}
		ss["tlsSettings"] = tls
	case "reality":
		if o.SNI == "" {
			return nil, fmt.Errorf("для reality нужен sni")
		}
		r := map[string]any{"serverNames": []string{o.SNI}, "fingerprint": "chrome"}
		if o.Dest != "" {
			r["dest"] = o.Dest
		}
		if o.PrivateKey != "" {
			r["privateKey"] = o.PrivateKey
		}
		if o.PublicKey != "" {
			r["publicKey"] = o.PublicKey
		}
		if o.ShortID != "" {
			r["shortIds"] = []string{o.ShortID}
		}
		ss["realitySettings"] = r
	default:
		return nil, fmt.Errorf("неизвестный security %q", security)
	}
	return ss, nil
}

// buildRules: api → системное правило инфры → правила модели → заглушка direct.
// Инфра-подсеть матчится ДО всех пользовательских правил: иначе общая
// блокировка приватных IP или catch-all перехватили бы доступ к инфре (§5 ТЗ).
func buildRules(st model.State, nodeID string) ([]any, error) {
	rules := []any{map[string]any{
		"type": "field", "inboundTag": []string{apiTag}, "outboundTag": apiTag,
	}}
	if addr, port := st.InfraDNSAddress(nodeID); addr != "" {
		// Throne обращается прямо к dnsmasq. Порт 53 для остальных
		// назначений по-прежнему обрабатывается перенаправлением.
		rules = append(rules, map[string]any{
			"type": "field", "ip": []string{addr}, "port": port,
			"network": "tcp,udp", "outboundTag": model.TagInfra,
		})
		var tags []string
		for _, in := range st.Inbounds {
			if in.Enabled && in.NodeID == nodeID {
				tags = append(tags, in.Tag)
			}
		}
		if len(tags) > 0 {
			rules = append(rules, map[string]any{
				"type": "field", "inboundTag": tags, "network": "tcp,udp",
				"port": "53", "outboundTag": model.TagInfraDNS,
			})
		}
		rules = append(rules, map[string]any{
			"type": "field", "domain": []string{"domain:" + st.DNS.Root}, "outboundTag": model.TagInfra,
		})
	}
	if subnet := st.InfraSubnet(nodeID); subnet != "" {
		rules = append(rules, map[string]any{
			"type": "field", "ip": []string{subnet}, "outboundTag": model.TagInfra,
		})
	}
	// Личные выходы клиентов: у WireGuard-пира нет xray-пользователя, поэтому
	// правило матчит адрес источника (allowedIPs пира). Стоит выше общих правил,
	// но ниже infra: инфра-подсеть всегда имеет приоритет (§5 ТЗ).
	if tags := st.ValidTags(nodeID); len(tags) > 0 {
		for _, c := range st.Clients {
			if !c.Enabled || c.Expired() || c.Egress == "" || !tags[c.Egress] {
				continue
			}
			for _, in := range st.Inbounds {
				if in.NodeID != nodeID || !in.Enabled || in.Kind != model.InboundWireGuard {
					continue
				}
				peer, ok := c.WireGuard[in.ID]
				if !ok || peer.Address == "" {
					continue
				}
				rules = append(rules, map[string]any{
					"type": "field", "source": []string{peer.Address}, "outboundTag": c.Egress,
				})
			}
		}
	}
	// Выход клиентской сети (карточка «Маршруты» → inbound.egress): трафик
	// инбаунда целиком, если клиент не переопределил выход лично. Раньше это
	// применял ядерный wgc-интерфейс; теперь — inboundTag в routing Xray.
	if tags := st.ValidTags(nodeID); len(tags) > 0 {
		for _, in := range st.Inbounds {
			if !in.Enabled || in.NodeID != nodeID || in.Egress == "" || !tags[in.Egress] {
				continue
			}
			rules = append(rules, map[string]any{
				"type": "field", "inboundTag": []string{in.Tag}, "outboundTag": in.Egress,
			})
		}
	}
	catchAll := false
	for _, r := range st.Routes {
		if !r.Enabled || (r.NodeID != "" && r.NodeID != nodeID) {
			continue
		}
		if !st.ValidTags(nodeID)[r.Outbound] {
			if r.NodeID == nodeID {
				return nil, fmt.Errorf("правило %q ссылается на несуществующий на этом узле исходящий %q",
					r.Name, r.Outbound)
			}
			// Глобальное правило с исходящим, которого на этом узле нет
			// (например, туннель начинается в другом месте), просто не применимо.
			continue
		}
		rule := map[string]any{"type": "field", "outboundTag": r.Outbound}
		conds := 0
		if len(r.User) > 0 {
			rule["user"] = r.User
			conds++
		}
		if len(r.Inbound) > 0 {
			rule["inboundTag"] = r.Inbound
			conds++
		}
		if len(r.Domain) > 0 {
			rule["domain"] = r.Domain
			conds++
		}
		if len(r.IP) > 0 {
			rule["ip"] = r.IP
			conds++
		}
		if r.Port != "" {
			rule["port"] = r.Port
			conds++
		}
		if r.Network != "" {
			rule["network"] = r.Network
			conds++
		}
		if conds == 0 {
			// xray отвергает правило без единого поля ("no effective fields"),
			// поэтому catch-all выражается явным network.
			rule["network"] = "tcp,udp"
			catchAll = true
		}
		rules = append(rules, rule)
	}
	if !catchAll {
		rules = append(rules, map[string]any{
			"type": "field", "network": "tcp,udp", "outboundTag": model.TagDirect,
		})
	}
	return rules, nil
}

func findNode(st model.State, id string) (model.Node, bool) {
	for _, n := range st.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return model.Node{}, false
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// splitAddr разбирает "host:port"; порт по умолчанию — fallback.
func splitAddr(addr string, fallback int) (string, int) {
	if addr == "" {
		return "127.0.0.1", fallback
	}
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return addr, fallback
	}
	port := fallback
	if p, ok := atoi(addr[i+1:]); ok && p > 0 {
		port = p
	}
	return addr[:i], port
}

func atoi(s string) (int, bool) {
	n := 0
	if s == "" {
		return 0, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}
