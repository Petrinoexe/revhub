package gen

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"revhub/internal/model"
)

// File — артефакт узла: имя, содержимое, права.
type File struct {
	Name    string
	Content string
	Mode    os.FileMode
}

type Manifest struct {
	Node        string            `json:"node"`
	GeneratedAt time.Time         `json:"generated_at"`
	Files       map[string]string `json:"files"` // имя → sha256
	Notes       []string          `json:"notes,omitempty"`
}

// Artifacts собирает полный набор файлов для узла.
func Artifacts(st model.State, nodeID string) ([]File, error) {
	if !filepath.IsLocal(nodeID) || filepath.Base(nodeID) != nodeID || nodeID == "." {
		return nil, fmt.Errorf("некорректный id узла %q", nodeID)
	}
	if _, ok := findNode(st, nodeID); !ok {
		return nil, fmt.Errorf("узел %q не найден", nodeID)
	}
	xj, err := XrayJSON(st, nodeID)
	if err != nil {
		return nil, err
	}
	files := []File{
		{Name: "xray.json", Content: string(xj), Mode: 0o640},
	}

	// Зона DNS клиентской сети: dnsmasq читает эти два файла, панель их только
	// рендерит — резолвер остаётся системным сервисом, а не частью панели.
	dnsFiles, dnsOn, err := DNSMasq(st, nodeID)
	if err != nil {
		return nil, err
	}
	if dnsOn {
		files = append(files,
			File{Name: DNSMasqConfName, Content: dnsFiles.Conf, Mode: 0o644},
			File{Name: DNSHostsFileName, Content: dnsFiles.Hosts, Mode: 0o644})
	}

	var wgNames []string
	for _, in := range st.Inbounds {
		if !in.Enabled || in.NodeID != nodeID || in.Kind != model.InboundWireGuard {
			continue
		}
		conf, err := ClientWGConf(st, in, nodeID)
		if err != nil {
			return nil, fmt.Errorf("инбаунд %s: %w", in.Tag, err)
		}
		name := in.WGInterface() + ".conf"
		files = append(files, File{Name: name, Content: conf, Mode: 0o600})
		wgNames = append(wgNames, name)
	}
	for _, t := range st.Tunnels {
		if !t.Enabled || !t.Touches(nodeID) {
			continue
		}
		if t.Kind != model.TunnelWG && t.Kind != model.TunnelWGReverse {
			continue
		}
		conf, err := WGConfig(st, t, nodeID)
		if err != nil {
			return nil, fmt.Errorf("туннель %s: %w", t.Name, err)
		}
		name := t.WGInterface() + ".conf"
		files = append(files, File{Name: name, Content: conf, Mode: 0o600})
		wgNames = append(wgNames, name)
	}
	sort.Strings(wgNames)
	// Инфраструктурная сеть — отдельный интерфейс и отдельная подсеть.
	infraConf, infraOn, err := InfraWGConf(st, nodeID)
	if err != nil {
		return nil, err
	}
	if infraOn {
		files = append(files, File{Name: "wg-infra.conf", Content: infraConf, Mode: 0o600})
		wgNames = append(wgNames, "wg-infra.conf")
		sort.Strings(wgNames)
	}
	useXray := len(wgNames) == 0 || NeedsXray(st, nodeID)
	// Узел выпускает трафик туннеля в интернет — значит, ему нужен ip_forward
	// не только до перезагрузки: PostUp wg-quick выставляет его в рантайме, но
	// systemd-sysctl при загрузке может вернуть 0, и туннель «поднят, но не водит».
	forward := infraOn
	for _, t := range st.Tunnels {
		if t.Enabled && t.ToNode == nodeID && t.ForwardPolicy &&
			(t.Kind == model.TunnelWG || t.Kind == model.TunnelWGReverse) {
			forward = true
		}
	}

	// Раскачка нужна только дозванивающейся стороне и только без keepalive:
	// слушатель не может разбудить пира, пока не знает его адреса.
	var kicks []kick
	for _, t := range st.Tunnels {
		if !t.Enabled || t.Keepalive > 0 || t.DialerNode() != nodeID {
			continue
		}
		if t.Kind != model.TunnelWG && t.Kind != model.TunnelWGReverse {
			continue
		}
		fromAddr, toAddr, err := t.Addrs()
		if err != nil {
			continue
		}
		peer := fromAddr
		if t.ListenerNode() == t.ToNode {
			peer = toAddr
		}
		kicks = append(kicks, kick{Iface: t.WGInterface(), Peer: peer, PeerPub: otherPubOf(t, nodeID)})
	}

	files = append(files,
		// Обратный туннель открывает дозванивающаяся сторона. Слушатель не
		// может её разбудить: пока сессии нет, у него нет адреса пира. Значит,
		// будить должен сам дозванивающийся — скрипт и таймер ниже делают это
		// только когда сессии действительно нет (keepalive мы не держим).
		kickFiles(kicks)...,
	)
	files = append(files,
		File{Name: "apply.sh", Content: applyScript(wgNames, useXray, NodePorts(st, nodeID), forward, kicks, dnsOn), Mode: 0o700},
		File{Name: "rollback.sh", Content: rollbackScript(wgNames, useXray, kicks), Mode: 0o700},
	)
	return files, nil
}

// NodePorts — порты, которые должны быть открыты снаружи на этом узле:
// клиентские инбаунды и слушатели туннелей. Без них свежий VPS с ufw
// принимает пакеты в пустоту, и «инбаунд не работает» выглядит как баг панели.
func NodePorts(st model.State, nodeID string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(port int, proto string) {
		if port <= 0 {
			return
		}
		spec := fmt.Sprintf("%d/%s", port, proto)
		if seen[spec] {
			return
		}
		seen[spec] = true
		out = append(out, spec)
	}
	for _, in := range st.Inbounds {
		if !in.Enabled || in.NodeID != nodeID {
			continue
		}
		proto := "tcp"
		if in.Kind == model.InboundWireGuard {
			proto = "udp"
		}
		add(in.Port, proto)
	}
	if st.Infra != nil && st.Infra.Enabled && st.Infra.NodeID == nodeID {
		add(st.Infra.ListenPort, "udp")
	}
	// Панель, открытая наружу, тоже должна быть в списке портов: иначе ufw
	// останется закрытым и «снаружи не открывается» будет выглядеть как баг.
	if st.Panel != nil && st.Panel.Expose && !st.Panel.LoopbackOnly() && st.Panel.NodeID == nodeID {
		add(st.Panel.Port(), "tcp")
	}
	for _, t := range st.Tunnels {
		if !t.Enabled || !t.Touches(nodeID) {
			continue
		}
		switch t.Kind {
		case model.TunnelWG, model.TunnelWGReverse:
			if t.ListenerNode() == nodeID {
				add(t.ListenPort, "udp")
			}
		case model.TunnelVLESS:
			if t.ToNode == nodeID {
				add(t.ListenPortT, "tcp")
			}
		}
	}
	return out
}

// NeedsXray identifies nodes with listeners or an Xray tunnel endpoint.
func NeedsXray(st model.State, nodeID string) bool {
	for _, in := range st.Inbounds {
		// Клиентский WireGuard — ядерный интерфейс: xray на таком узле не нужен.
		if in.Enabled && in.NodeID == nodeID && in.Kind != model.InboundWireGuard {
			return true
		}
	}
	for _, t := range st.Tunnels {
		if t.Enabled && (t.FromNode == nodeID || t.Kind == model.TunnelVLESS && t.ToNode == nodeID) {
			return true
		}
	}
	return false
}

// ClientWGConf рендерит wg-quick конфиг клиентской сети для узла: один
// ядерный интерфейс на инбаунд, все клиенты в одной подсети. Пир видит пира
// (маршрут /32 в тот же интерфейс), наружу трафик уходит NAT'ом самого узла
// либо в туннель, если инбаунд так настроен.
func ClientWGConf(st model.State, in model.Inbound, nodeID string) (string, error) {
	if in.NodeID != nodeID {
		return "", fmt.Errorf("инбаунд %q не на узле %s", in.Tag, nodeID)
	}
	wg := in.WireGuard
	if wg == nil || wg.PrivateKey == "" || wg.PublicKey == "" {
		return "", fmt.Errorf("нет ключей WireGuard")
	}
	if pub := wgPublicKeyOf(wg.PrivateKey); pub == "" || pub != wg.PublicKey {
		return "", fmt.Errorf("неверная пара ключей WireGuard")
	}
	addr := wg.ServerAddressPrefix()
	if addr == "" {
		return "", fmt.Errorf("некорректная подсеть %q", wg.Subnet)
	}
	if in.Port <= 0 || in.Port > 65535 {
		return "", fmt.Errorf("некорректный порт %d", in.Port)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# revhub: клиенты WireGuard — инбаунд %q на узле %s\n", in.Tag, nodeID)
	fmt.Fprintf(&b, "# сеть %s: клиенты видят друг друга, выход — %s\n", addr, egressText(st, in))
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "Address = %s\n", addr)
	fmt.Fprintf(&b, "PrivateKey = %s\n", wg.PrivateKey)
	fmt.Fprintf(&b, "ListenPort = %d\n", in.Port)
	fmt.Fprintf(&b, "MTU = %d\n", model.DefaultWireGuardMTU)

	// Трафик пир→пир идёт через этот же интерфейс, значит это форвардинг:
	// без ip_forward и разрешения в forward-цепочке он молча умирает.
	b.WriteString("PostUp = " + soft("sysctl -q -w net.ipv4.ip_forward=1",
		"ip_forward не включился (read-only /proc/sys?) — включи его на узле сам") + "\n")
	b.WriteString("PostUp = " + soft("printf '2\\n' > /proc/sys/net/ipv4/conf/%i/rp_filter",
		"rp_filter не сброшен в loose — часть пакетов может фильтроваться") + "\n")

	// Разрешение в FORWARD — именно в общей цепочке filter/FORWARD, а не в
	// своей nft-таблице: ufw и docker держат там же свои правила и дропают
	// раньше; приватная base-цепочка чужой drop не отменяет. iptables на
	// современных системах — это тот же nftables, поэтому правило одно.
	b.WriteString("PostUp = " + soft("iptables -I FORWARD -i %i -j ACCEPT",
		"правило FORWARD не добавилось — клиенты не пройдут при политике drop") + "\n")
	b.WriteString("PostUp = " + soft("iptables -I FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
		"правило FORWARD для обратного трафика не добавилось") + "\n")
	b.WriteString("PostDown = iptables -D FORWARD -i %i -j ACCEPT 2>/dev/null || true\n")
	b.WriteString("PostDown = iptables -D FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true\n")

	// NAT — в своей таблице: там нет чужих правил, и удаление нашего drop-in'а
	// не задевает остальное.
	table := nftTable(in.WGInterface())
	// Уже включённый NAT: правила отдельных пиров не должны дублировать таблицу.
	natTunnels := map[int]bool{}
	directOverride := false
	switch {
	case strings.HasPrefix(in.Egress, model.TagTunnel):
		// Клиенты выходят через туннель: маршрут по источнику в его таблицу.
		name := strings.TrimPrefix(in.Egress, model.TagTunnel)
		t, ok := findTunnel(st, name)
		if !ok || t.FromNode != nodeID {
			return "", fmt.Errorf("нет включённого туннеля %s на узле %s", name, nodeID)
		}
		// Правило по входному интерфейсу, а не по адресу источника: `from
		// 10.88.0.0/24` перехватывало бы и собственный трафик узла (dnsmasq
		// отвечает с адреса этого же интерфейса) и уводило его в туннель.
		// Пир-пир остаётся в своей сети: в таблице туннеля сначала ищется
		// маршрут на подсеть через %i, и только остальное попадает в default.
		fmt.Fprintf(&b, "PostUp = ip -4 route replace %s dev %%i table %d\n", wg.Subnet, t.Mark)
		fmt.Fprintf(&b, "PostDown = ip -4 route del %s dev %%i table %d 2>/dev/null || true\n", wg.Subnet, t.Mark)
		fmt.Fprintf(&b, "PostUp = ip rule del iif %%i lookup %d 2>/dev/null || true; ip rule add iif %%i lookup %d pref 32000\n",
			t.Mark, t.Mark)
		// Пустая таблица = правило промахивается и трафик уходит напрямую
		// (ядро продолжает поиск по следующему правилу). Молчать об этом
		// нельзя: снаружи выглядит как «в туннель не хочет идти».
		fmt.Fprintf(&b, "PostUp = ip -4 route show table %d default | grep -q . || echo \"[revhub] таблица %d без default: туннель %s не поднят, клиенты пойдут напрямую\" >&2\n",
			t.Mark, t.Mark, name)
		fmt.Fprintf(&b, "PostDown = ip rule del iif %%i lookup %d 2>/dev/null || true\n", t.Mark)
		// Подмена источника на адрес туннеля. Выходной узел — «тупой шлюз»:
		// он знает только адрес дальнего конца туннеля, и его WireGuard
		// выбрасывает пакеты с чужими адресами по AllowedIPs. NAT на хабе
		// делает выход независимым от того, какие клиентские подсети ему
		// прописали (на контейнерных VPS это частая история), а обратные
		// пакеты conntrack раскручивает сам.
		natiface := t.WGInterface()
		if len(natiface) > 15 {
			return "", fmt.Errorf("слишком длинное имя интерфейса туннеля %q", natiface)
		}
		writeTunnelNAT(&b, wg.Subnet, table, natiface)
		natTunnels[t.Mark] = true
	default:
		// Общий выход в интернет: NAT наружу, но не между пирами.
		nat := []string{
			fmt.Sprintf(`add table ip %s`, table),
			fmt.Sprintf(`add chain ip %s postrouting { type nat hook postrouting priority 100; }`, table),
			fmt.Sprintf(`add rule ip %s postrouting iifname "%%i" oifname != "%%i" masquerade`, table),
		}
		b.WriteString("PostUp = if command -v nft >/dev/null; then printf '%s\\n' " + shellJoin(nat) + " | nft -f -; else iptables -t nat -I POSTROUTING -s " + wg.Subnet + " ! -o %i -j MASQUERADE; fi\n")
		b.WriteString("PostDown = if command -v nft >/dev/null; then nft delete table ip " + table + " 2>/dev/null || true; else iptables -t nat -D POSTROUTING -s " + wg.Subnet + " ! -o %i -j MASQUERADE 2>/dev/null || true; fi\n")
		directOverride = true
	}

	// Личные выходы пиров: правило по адресу источника с более высоким
	// приоритетом, чем правило инбаунда (31900 против 32000). Один клиент
	// может идти в свой выходной узел, пока остальные идут в другой туннель
	// или напрямую.
	for _, c := range st.Clients {
		if c.Egress == "" || !c.Enabled || c.Expired() || !contains(c.Inbounds, in.ID) {
			continue
		}
		peer, ok := c.WireGuard[in.ID]
		if !ok || peer.Address == "" {
			continue
		}
		ip := strings.TrimSuffix(peer.Address, "/32")
		bucket := "main"
		if strings.HasPrefix(c.Egress, model.TagTunnel) {
			name := strings.TrimPrefix(c.Egress, model.TagTunnel)
			t, ok := findTunnel(st, name)
			if !ok || t.FromNode != nodeID {
				return "", fmt.Errorf("клиент %s: нет включённого туннеля %s на узле %s", c.Email, name, nodeID)
			}
			bucket = strconv.Itoa(t.Mark)
			if !natTunnels[t.Mark] {
				natTunnels[t.Mark] = true
				writeTunnelNAT(&b, wg.Subnet, table, t.WGInterface())
			}
		} else if c.Egress == model.TagDirect {
			if !directOverride {
				directOverride = true
				writeDirectNAT(&b, wg.Subnet, table+"_d")
			}
		} else {
			continue
		}
		fmt.Fprintf(&b, "PostUp = ip rule del from %s/32 lookup %s pref 31900 2>/dev/null || true; ip rule add from %s/32 lookup %s pref 31900\n",
			ip, bucket, ip, bucket)
		fmt.Fprintf(&b, "PostDown = ip rule del from %s/32 lookup %s pref 31900 2>/dev/null || true\n", ip, bucket)
	}

	peers := 0
	for _, c := range st.Clients {
		if !c.Enabled || c.Expired() || !contains(c.Inbounds, in.ID) {
			continue
		}
		peer, ok := c.WireGuard[in.ID]
		if !ok {
			return "", fmt.Errorf("у клиента %s нет ключей WireGuard", c.Email)
		}
		for _, key := range []string{peer.PublicKey, peer.PresharedKey} {
			if raw, err := base64.StdEncoding.DecodeString(key); err != nil || len(raw) != 32 {
				return "", fmt.Errorf("у клиента %s некорректный ключ WireGuard", c.Email)
			}
		}
		if _, ok := modelPeerPrefix(peer.Address); !ok {
			return "", fmt.Errorf("у клиента %s некорректный адрес WireGuard", c.Email)
		}
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(&b, "# %s\n", c.Email)
		fmt.Fprintf(&b, "PublicKey = %s\n", peer.PublicKey)
		fmt.Fprintf(&b, "PresharedKey = %s\n", peer.PresharedKey)
		fmt.Fprintf(&b, "AllowedIPs = %s\n", peer.Address)
		peers++
	}
	if peers == 0 {
		// Инбаунд без клиентов — законное состояние: интерфейс поднимается,
		// пиры появятся, когда клиентов создадут. Раньше это валило применение
		// и выглядело как «инбаунд не создался».
		b.WriteString("\n# клиентов пока нет: пиры появятся при их создании\n")
	}
	return b.String(), nil
}

// printfNewline — `printf '%s\n' ` для nft-скрипта. Отдельной raw-строкой,
// чтобы Go не превратил \n в перевод строки и не разорвал строку конфига.
const printfNewline = `printf '%s\n' `

// writeDirectNAT — обычный NAT узла для пира, которому выход переопределён на
// «напрямую», когда вся сеть уходит в туннель.
func writeDirectNAT(b *strings.Builder, subnet, table string) {
	rules := []string{
		fmt.Sprintf(`add table ip %s`, table),
		fmt.Sprintf(`add chain ip %s postrouting { type nat hook postrouting priority 100; }`, table),
		fmt.Sprintf(`add rule ip %s postrouting ip saddr %s oifname != "%%i" masquerade`, table, subnet),
	}
	// printf '%s\n' — raw-строка: в обычной Go-строке \n стал бы переводом
	// строки, и wg-quick увидел бы обрывок конфига («Line unrecognized»).
	b.WriteString("PostUp = " + soft("if command -v nft >/dev/null; then "+printfNewline+shellJoin(rules)+
		" | nft -f -; else iptables -t nat -I POSTROUTING -s "+subnet+" -j MASQUERADE; fi",
		"не удалось включить NAT для пира с выходом напрямую") + "\n")
	b.WriteString("PostDown = " + soft("if command -v nft >/dev/null; then nft delete table ip "+table+
		" 2>/dev/null || true; else iptables -t nat -D POSTROUTING -s "+subnet+" -j MASQUERADE 2>/dev/null || true; fi",
		"не удалось снять NAT для пира") + "\n")
}

// writeTunnelNAT подменяет источник клиентских пакетов на адрес туннеля:
// выходной узел знает только его (его AllowedIPs), а чужие адреса отбрасывает.
func writeTunnelNAT(b *strings.Builder, subnet, table, natiface string) {
	rules := []string{
		fmt.Sprintf(`add table ip %s`, table),
		fmt.Sprintf(`add chain ip %s postrouting { type nat hook postrouting priority 100; }`, table),
		fmt.Sprintf(`add rule ip %s postrouting ip saddr %s oifname "%s" masquerade`, table, subnet, natiface),
	}
	b.WriteString("PostUp = " + soft("if command -v nft >/dev/null; then "+printfNewline+shellJoin(rules)+
		" | nft -f -; else iptables -t nat -I POSTROUTING -s "+subnet+" -o "+natiface+" -j MASQUERADE; fi",
		"не удалось включить подмену адреса в туннель — выход отбросит клиентские пакеты") + "\n")
	b.WriteString("PostDown = " + soft("if command -v nft >/dev/null; then nft delete table ip "+table+
		" 2>/dev/null || true; else iptables -t nat -D POSTROUTING -s "+subnet+" -o "+natiface+
		" -j MASQUERADE 2>/dev/null || true; fi", "не удалось снять подмену адреса") + "\n")
}

// egressText — человекочитаемое «куда выпускает» для шапки конфига.
func egressText(st model.State, in model.Inbound) string {
	if name, ok := strings.CutPrefix(in.Egress, model.TagTunnel); ok {
		return "в туннель " + name
	}
	return "NAT этого узла"
}

func wgPublicKeyOf(private string) string {
	raw, err := base64.StdEncoding.DecodeString(private)
	if err != nil || len(raw) != 32 {
		return ""
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
}

func modelPeerPrefix(address string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(address)
	if err != nil || p.Bits() != 32 {
		return netip.Prefix{}, false
	}
	return p, true
}

// nftTable — имя nft-таблицы для интерфейса: короткое и без спецсимволов.
func nftTable(iface string) string {
	sum := sha256.Sum256([]byte(iface))
	return fmt.Sprintf("revhub_%x", sum[:6])
}

// soft делает хук необязательным: сбой не должен валить интерфейс. В
// контейнерах и на VPS с read-only /proc/sys запись sysctl и rp_filter
// запрещена, iptables может отсутствовать — раньше это роняло wg-quick,
// и созданный интерфейс удалялся целиком.
func soft(cmd, why string) string {
	return cmd + ` 2>/dev/null || echo "[revhub] ` + why + `" >&2`
}

// shellJoin собирает строки для `printf '%s\n' ...` в конфиге wg-quick.
func shellJoin(items []string) string {
	quoted := make([]string, len(items))
	for i, s := range items {
		quoted[i] = "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return strings.Join(quoted, " ")
}

func findTunnel(st model.State, name string) (model.Tunnel, bool) {
	for _, t := range st.Tunnels {
		if t.Name == name && t.Enabled {
			return t, true
		}
	}
	return model.Tunnel{}, false
}

// WGConfig рендерит wg-quick конфиг для одного конца туннеля.
//
// Инвариант: Table = off всегда. Маршрутизацию в туннель делает только
// сторона From, через fwmark + отдельную таблицу; сторона To выпускает
// трафик наружу (при ForwardPolicy) и не трогает свои маршруты.
func WGConfig(st model.State, t model.Tunnel, nodeID string) (string, error) {
	if !t.Touches(nodeID) {
		return "", fmt.Errorf("узел %q не участвует в туннеле", nodeID)
	}
	fromAddr, toAddr, err := t.Addrs()
	if err != nil {
		return "", err
	}
	listener, dialer := t.ListenerNode(), t.DialerNode()
	isFrom := nodeID == t.FromNode

	addr, otherPub := toAddr, t.FromKeyPub
	if isFrom {
		addr, otherPub = fromAddr, t.ToKeyPub
	}
	// В общей сети концы туннеля — обычные /32: подсеть уже занята клиентским
	// интерфейсом, и второй адрес с той же маской сломал бы маршруты. Старые
	// состояния (отдельная /30) рендерим как раньше.
	mask := "/30"
	if t.FromAddr != "" && t.ToAddr != "" {
		mask = "/32"
	}
	private := pick(isFrom, t.FromKeyPriv, t.ToKeyPriv)
	for _, key := range []string{private, otherPub} {
		raw, err := base64.StdEncoding.DecodeString(key)
		if err != nil || len(raw) != 32 || base64.StdEncoding.EncodeToString(raw) != key {
			return "", fmt.Errorf("некорректный ключ WireGuard на узле %s", nodeID)
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# revhub: туннель %q, вид %s, узел %s\n", t.Name, t.Kind, nodeID)
	fmt.Fprintf(&b, "# направление трафика: %s → %s\n", t.FromNode, t.ToNode)
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "Address = %s%s\n", addr, mask)
	fmt.Fprintf(&b, "PrivateKey = %s\n", private)
	b.WriteString("Table = off\n")
	fmt.Fprintf(&b, "MTU = %d\n", 1380)

	if nodeID == listener {
		fmt.Fprintf(&b, "ListenPort = %d\n", t.ListenPort)
	}
	if isFrom {
		// Единственная точка стыка двух плоскостей: метка → таблица → интерфейс.
		// Плюс host-route до дальнего конца в main: по нему панель ходит на
		// выходной по SSH через туннель, не задевая остальной трафик.
		// PreUp — защита от тихого перехвата чужой таблицы: если в ней уже есть
		// default от чужого интерфейса (ручной wg0 на этой же машине), apply
		// падает с объяснением, а не уводит чужой трафик в наш туннель. Свой
		// собственный застрявший default (остался после падения, когда PostDown
		// не выполнился) снимаем — иначе туннель не поднимается уже никогда,
		// а клиенты молча идут напрямую.
		fmt.Fprintf(&b, "PreUp = sh -c 'r=$(ip -4 route show table %d default 2>/dev/null | head -n1); case \"$r\" in \"\") exit 0;; *\"dev %s\"*) ip -4 route flush table %d; echo \"[revhub] снят устаревший default из таблицы %d\";; *) echo \"[revhub] таблица %d занята чужим default ($r) — смени метку туннеля\" >&2; exit 1;; esac'\n",
			t.Mark, t.WGInterface(), t.Mark, t.Mark, t.Mark)
		fmt.Fprintf(&b, "PostUp = ip -4 route replace %s/32 dev %%i\n", toAddr)
		fmt.Fprintf(&b, "PostDown = ip -4 route del %s/32 dev %%i 2>/dev/null || true\n", toAddr)
		fmt.Fprintf(&b, "PostUp = ip rule add fwmark %d lookup %d 2>/dev/null || true\n", t.Mark, t.Mark)
		fmt.Fprintf(&b, "PostUp = ip -4 route replace default dev %%i table %d\n", t.Mark)
		// Проверка, что таблица действительно получила default: без него
		// правило по iif на клиентском интерфейсе «промахивается» и трафик
		// уходит напрямую — самый незаметный из возможных отказов.
		fmt.Fprintf(&b, "PostUp = ip -4 route show table %d default | grep -q . || echo \"[revhub] в таблице %d нет default: туннель не маршрутизирует, клиенты пойдут напрямую\" >&2\n",
			t.Mark, t.Mark)
		// Replies arrive on WireGuard, while the unmarked reverse path uses the WAN.
		b.WriteString("PostUp = " + soft("printf '2\\n' > /proc/sys/net/ipv4/conf/%i/rp_filter",
			"rp_filter не сброшен в loose — часть пакетов может фильтроваться") + "\n")
		fmt.Fprintf(&b, "PostDown = ip rule del fwmark %d lookup %d 2>/dev/null || true\n", t.Mark, t.Mark)
		fmt.Fprintf(&b, "PostDown = ip -4 route flush table %d 2>/dev/null || true\n", t.Mark)
	}
	if !isFrom {
		// Обратный путь к концу туннеля на хабе: Table = off, маршрут свой.
		fmt.Fprintf(&b, "PostUp = ip -4 route replace %s/32 dev %%i\n", fromAddr)
		fmt.Fprintf(&b, "PostDown = ip -4 route del %s/32 dev %%i 2>/dev/null || true\n", fromAddr)
	}
	if !isFrom && t.ForwardPolicy {
		if err := writeNAT(&b, t, fromAddr, egressSubnets(st, t)); err != nil {
			return "", err
		}
	}

	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", otherPub)
	if nodeID == dialer {
		// Keepalive — только по явному запросу (t.Keepalive > 0). По умолчанию
		// его нет: соединение должен открывать дозванивающийся узел, а не
		// слушающий, и лишний фоновый трафик нам не нужен.
		if t.Keepalive > 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", t.Keepalive)
		}
		// Endpoint — адрес слушающей стороны. Порт берём из туннеля, а не из
		// public_addr узла: там лежит порт для клиентов (443), он тут не годится.
		host := hostOnly(mustNode(st, listener).PublicAddr)
		if strings.ContainsAny(host, "\r\n#") {
			return "", fmt.Errorf("некорректный адрес WireGuard на узле %s", listener)
		}
		port := t.ListenPort
		if t.PublicPort > 0 {
			port = t.PublicPort
		}
		fmt.Fprintf(&b, "Endpoint = %s\n", net.JoinHostPort(host, strconv.Itoa(port)))
	}
	if isFrom {
		b.WriteString("AllowedIPs = 0.0.0.0/0\n")
	} else {
		// Обратный путь: кроме адреса дальнего конца принимаем подсети
		// клиентских сетей, которые выпускаются через этот туннель. WireGuard
		// фильтрует источник по AllowedIPs и молча выбрасывает пакеты с чужим
		// адресом — без этого выход не видит клиентов вовсе.
		parts := append([]string{fromAddr + "/32"}, egressSubnets(st, t)...)
		fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(parts, ", "))
	}
	return b.String(), nil
}

func mustNode(st model.State, id string) model.Node {
	n, _ := findNode(st, id)
	return n
}

// writeNAT включает форвардинг и NAT на выходном узле туннеля. Источники —
// адрес дальнего конца туннеля и подсети клиентских сетей, которые через этот
// туннель выпускаются: без них трафик клиентов уходил бы наружу с приватным
// адресом 10.88.0.x и не возвращался.
func writeNAT(b *strings.Builder, t model.Tunnel, fromAddr string, clients []string) error {
	sum := sha256.Sum256([]byte(t.WGInterface()))
	table := fmt.Sprintf("revhub_%x", sum[:6])
	srcs := []string{fromAddr + "/32"}
	for _, c := range clients {
		if c != "" && c != fromAddr+"/32" {
			srcs = append(srcs, c)
		}
	}
	selector := `iifname "%i" ip saddr { ` + strings.Join(srcs, ", ") + ` } oifname != "%i"`
	var legacy []string
	for _, s := range srcs {
		legacy = append(legacy, "-s "+s+" ! -o %i")
	}
	if iface := t.EgressIface; iface != "" {
		if len(iface) > 15 || strings.ContainsFunc(iface, func(c rune) bool {
			return !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_=+.-", c))
		}) {
			return fmt.Errorf("некорректное имя выходного интерфейса %q", iface)
		}
		fmt.Fprintf(b, "PostUp = ip link show dev %q >/dev/null\n", iface)
		selector = `iifname "%i" ip saddr { ` + strings.Join(srcs, ", ") + ` } oifname ` + strconv.Quote(iface)
		legacy = nil
		for _, s := range srcs {
			legacy = append(legacy, "-s "+s+" -o "+iface)
		}
	}
	b.WriteString("PostUp = " + soft("sysctl -q -w net.ipv4.ip_forward=1",
		"ip_forward не включился (read-only /proc/sys?) — включи его на узле сам") + "\n")
	// Обратный маршрут к клиентским сетям через туннель: без него строгий
	// rp_filter выбрасывает пакеты с чужим адресом источника, а ответы не
	// находят дорогу назад. Table = off, поэтому маршрут ставим сами.
	for _, c := range clients {
		fmt.Fprintf(b, "PostUp = ip -4 route replace %s dev %%i\n", c)
		fmt.Fprintf(b, "PostDown = ip -4 route del %s dev %%i 2>/dev/null || true\n", c)
	}
	b.WriteString("PostUp = " + soft("printf '2\\n' > /proc/sys/net/ipv4/conf/%i/rp_filter",
		"rp_filter не сброшен в loose — часть пакетов может фильтроваться") + "\n")
	// Пакеты клиентов приходят в туннель и уходят наружу — это форвардинг.
	// ufw и docker держат в filter/FORWARD политику drop, поэтому разрешаем
	// явно, в общей цепочке: приватная таблица чужой drop не отменяет.
	b.WriteString("PostUp = " + soft("iptables -I FORWARD -i %i -j ACCEPT",
		"правило FORWARD не добавилось — клиенты не пройдут при политике drop") + "\n")
	b.WriteString("PostUp = " + soft("iptables -I FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
		"правило FORWARD для обратного трафика не добавилось") + "\n")
	b.WriteString("PostDown = iptables -D FORWARD -i %i -j ACCEPT 2>/dev/null || true\n")
	b.WriteString("PostDown = iptables -D FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true\n")
	// Create a separate table so nftables works even on a fresh exit node.
	fallbackUp := make([]string, len(legacy))
	fallbackDown := make([]string, len(legacy))
	for i, rule := range legacy {
		fallbackUp[i] = "iptables -t nat -I POSTROUTING " + rule + " -j MASQUERADE"
		fallbackDown[i] = "iptables -t nat -D POSTROUTING " + rule + " -j MASQUERADE 2>/dev/null || true"
	}
	fmt.Fprintf(b, "PostUp = if command -v nft >/dev/null; then printf '%%s\\n' 'add table ip %s' 'add chain ip %s postrouting { type nat hook postrouting priority srcnat; }' 'add rule ip %s postrouting %s masquerade' | nft -f -; else %s; fi\n",
		table, table, table, selector, strings.Join(fallbackUp, "; "))
	fmt.Fprintf(b, "PostDown = if command -v nft >/dev/null; then nft delete table ip %s; else %s; fi\n",
		table, strings.Join(fallbackDown, "; "))
	return nil
}

// egressSubnets — подсети клиентских сетей, которые выпускаются через туннель.
func egressSubnets(st model.State, t model.Tunnel) []string {
	var out []string
	seen := map[string]bool{}
	for _, in := range st.Inbounds {
		if !in.Enabled || in.Kind != model.InboundWireGuard || in.NodeID != t.FromNode {
			continue
		}
		if in.Egress != model.TagTunnel+t.Name || in.WireGuard == nil {
			continue
		}
		s := in.WireGuard.Subnet
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// hostOnly отрезает порт от "host:port"; для IPv6 в скобках сохраняет адрес.
func hostOnly(addr string) string {
	if addr == "" {
		return "127.0.0.1"
	}
	if net.ParseIP(addr) != nil {
		return addr
	}
	if strings.HasPrefix(addr, "[") {
		if i := strings.LastIndex(addr, "]"); i > 0 {
			return addr[1:i]
		}
	}
	if i := strings.LastIndex(addr, ":"); i > 0 && !strings.Contains(addr[i+1:], ":") {
		if _, ok := atoi(addr[i+1:]); ok {
			return addr[:i]
		}
	}
	return addr
}

func pick(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

// kick — кого и по какому интерфейсу «раскачивать» на дозванивающейся стороне.
type kick struct {
	Iface   string
	Peer    string // адрес пира в подсети туннеля (для журнала/диагностики)
	PeerPub string // публичный ключ пира — им и «будим» сессию
}

// otherPubOf — публичный ключ противоположной стороны туннеля.
func otherPubOf(t model.Tunnel, nodeID string) string {
	if nodeID == t.FromNode {
		return t.ToKeyPub
	}
	return t.FromKeyPub
}

// kickFiles рендерит скрипт и таймер, которые держат сессию обратного туннеля
// без PersistentKeepalive. Скрипт шлёт один пакет только когда сессии нет:
// в норме (сессия жива) фонового трафика нет вовсе.
func kickFiles(kicks []kick) []File {
	var out []File
	for _, k := range kicks {
		script := fmt.Sprintf(`#!/bin/sh
# revhub: раскачка обратного туннеля %[1]s.
# Соединение открывает дозванивающаяся сторона; слушатель не может её разбудить,
# пока не знает адреса пира. Поэтому при отсутствии/устаревании сессии ненадолго
# включаем keepalive: WireGuard сразу шлёт пакет, хендшейк уходит от нас к
# слушателю, после чего keepalive выключается и фонового трафика нет.
# Никаких внешних утилит (ping/curl) — только wg, который здесь точно есть.
set -u
iface=%[1]s
peerpub=%[3]s
peer_ip=%[2]s
h=$(wg show "$iface" latest-handshakes 2>/dev/null | awk '{print $2}' | sort -n | tail -1)
now=$(date +%%s)
if [ -z "${h:-}" ] || [ "${h:-0}" -eq 0 ] || [ $((now-h)) -gt 150 ]; then
  wg set "$iface" peer "$peerpub" persistent-keepalive 1 2>/dev/null || exit 0
  sleep 2
  wg set "$iface" peer "$peerpub" persistent-keepalive off 2>/dev/null || true
fi
`, k.Iface, k.Peer, k.PeerPub)
		out = append(out, File{Name: "kick-" + k.Iface + ".sh", Content: script, Mode: 0o755})
		out = append(out, File{Name: "revhub-kick-" + k.Iface + ".service",
			Content: fmt.Sprintf(`[Unit]
Description=revhub: сессия туннеля %s
After=wg-quick@%s.service

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/revhub/kick-%s.sh
`, k.Iface, k.Iface, k.Iface), Mode: 0o644})
		out = append(out, File{Name: "revhub-kick-" + k.Iface + ".timer",
			Content: fmt.Sprintf(`[Unit]
Description=revhub: держать сессию туннеля %s

[Timer]
OnBootSec=90s
OnUnitActiveSec=60s
AccuracySec=10s

[Install]
WantedBy=timers.target
`, k.Iface), Mode: 0o644})
	}
	return out
}

func applyScript(wgFiles []string, useXray bool, ports []string, forward bool, kicks []kick, dnsOn bool) string {
	var b strings.Builder
	b.WriteString("#!/usr/bin/env bash\n")
	b.WriteString("# Сгенерировано revhub. Порядок важен: сначала туннели, потом ядро.\n")
	b.WriteString("set -euo pipefail\ncd \"$(dirname \"$0\")\"\n")
	if len(ports) > 0 {
		// ufw по умолчанию есть на Ubuntu/Debian; firewalld трогаем, только если он
		// действительно управляет этой машиной. Ошибки не валят применение.
		b.WriteString("if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status: active'; then\n")
		for _, p := range ports {
			fmt.Fprintf(&b, "  ufw allow %q >/dev/null 2>&1 || true\n", p)
		}
		b.WriteString("fi\n")
		b.WriteString("if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then\n")
		for _, p := range ports {
			port, proto, _ := strings.Cut(p, "/")
			fmt.Fprintf(&b, "  firewall-cmd --permanent --add-port=%q >/dev/null 2>&1 || true\n", port+"/"+proto)
		}
		b.WriteString("  firewall-cmd --reload >/dev/null 2>&1 || true\nfi\n")
	}
	if useXray {
		// Xray перезапускается ДО подъёма WG-интерфейсов. Старая конфигурация
		// могла держать UDP-порт клиентского инбаунда (userspace-wireguard в
		// Xray): ядро биндит порт в момент `ip link set up`, и порядок
		// «сначала WG, потом Xray» даёт вечный тупик — порт занят старым Xray,
		// а новый конфиг без этого инбаунда не применяется, потому что
		// применение падает.
		b.WriteString(`XRAY_BIN=${XRAY_BIN:-xray}
XRAY_CONFIG=${XRAY_CONFIG:-/usr/local/etc/xray/config.json}
STATE_DIR=${STATE_DIR:-/etc/revhub}
"$XRAY_BIN" -test -c xray.json
install -d "$(dirname "$XRAY_CONFIG")"
install -d -m 750 "$STATE_DIR/last-good"
had_config=0
if [ -f "$XRAY_CONFIG" ]; then
  cp -a "$XRAY_CONFIG" "$STATE_DIR/last-good/xray.json"
  had_config=1
fi
candidate=$(mktemp "${XRAY_CONFIG}.revhub.XXXXXX")
trap 'rm -f -- "$candidate"' EXIT
if ! install -m 640 xray.json "$candidate" 2>/dev/null; then
  echo "[revhub] не записался xray.json (каталог только для чтения?) — конфиг ядра не обновится" >&2
  exit 1
fi
# Конфиг читает и панель (диагностика сравнивает sha256). Панель работает
# непривилегированно, поэтому отдаём файл группе каталога состояния, а не миру.
cfg_group=$(stat -c %G "$STATE_DIR" 2>/dev/null || true)
if [ -n "$cfg_group" ] && [ "$cfg_group" != root ]; then chgrp "$cfg_group" "$candidate" 2>/dev/null || true; fi
mv -fT -- "$candidate" "$XRAY_CONFIG"
if ! systemctl restart xray || ! sleep 1 || ! systemctl is-active --quiet xray; then
  echo "[revhub] Xray не запустился. Проверь journalctl -u xray" >&2
  if [ "$had_config" = 1 ]; then
    cp -a "$STATE_DIR/last-good/xray.json" "$candidate"
    mv -fT -- "$candidate" "$XRAY_CONFIG"
    systemctl restart xray
  else
    rm -f -- "$XRAY_CONFIG"
  fi
  exit 1
fi
`)
	}
	if len(wgFiles) > 0 {
		b.WriteString("install -d -m 700 /etc/wireguard\n")
		// Инфра-интерфейс обновляется без перезапуска: wg syncconf меняет
		// пиров на живом интерфейсе, не сбрасывая маршруты, NAT и сессии.
		for _, f := range wgFiles {
			if f != "wg-infra.conf" {
				continue
			}
			b.WriteString(`
if ! install -m 600 wg-infra.conf /etc/wireguard/wg-infra.conf 2>/dev/null; then
  echo "[revhub] не записался /etc/wireguard/wg-infra.conf (только для чтения?)" >&2
  exit 1
fi
if ip link show dev wg-infra >/dev/null 2>&1; then
  sync_tmp=$(mktemp)
  if wg-quick strip /etc/wireguard/wg-infra.conf > "$sync_tmp" 2>/dev/null && wg syncconf wg-infra "$sync_tmp"; then
    rm -f -- "$sync_tmp"
    echo "[revhub] wg-infra: пиры синхронизированы без перезапуска"
  else
    rm -f -- "$sync_tmp"
    echo "[revhub] wg-infra: syncconf не удался, перезапускаю интерфейс" >&2
    wg-quick down wg-infra >/dev/null 2>&1 || true
    wg-quick up wg-infra
  fi
else
  wg-quick up wg-infra
  echo "[revhub] wg-infra: интерфейс поднят"
fi
if [ -d /run/systemd/system ]; then systemctl enable wg-quick@wg-infra.service >/dev/null 2>&1 || true; fi
`)
		}
		// Удалённый из панели туннель оставляет на узле живой интерфейс, его
		// адрес, метку и таблицу маршрутов. Новый туннель получает те же
		// значения (адресация считается по состоянию) и падает на
		// «Address already in use». Поэтому снимаем всё наше, чего нет в
		// текущем наборе. Чужие конфиги (ручной wg0) не трогаем: у них нет
		// нашего заголовка.
		b.WriteString(`keep="`)
		for _, f := range wgFiles {
			b.WriteString(" " + f)
		}
		b.WriteString(` "
for stale in /etc/wireguard/*.conf; do
  [ -e "$stale" ] || continue
  grep -q '^# revhub:' "$stale" || continue
  case "$keep" in *" $(basename "$stale") "*) continue;; esac
  wg-quick down "$(basename "$stale" .conf)" 2>/dev/null || true
  rm -f -- "$stale"
  echo "[revhub] снят устаревший интерфейс $(basename "$stale" .conf)"
done
# Интерфейс мог остаться без конфига: переименовали тег, файл снесли руками.
# Префикс wgc- наш, такие снимаем по имени, а не по наличию файла.
keep_ifaces=""
for f in $keep; do keep_ifaces="$keep_ifaces ${f%.conf}"; done
for iface in $(ls /sys/class/net 2>/dev/null | grep '^wgc-' || true); do
  case "$keep_ifaces " in *" $iface "*) continue;; esac
  wg-quick down "$iface" >/dev/null 2>&1 || true
  ip link show dev "$iface" >/dev/null 2>&1 && ip link delete dev "$iface" >/dev/null 2>&1 || true
  echo "[revhub] снят устаревший интерфейс $iface"
done
`)
	}
	for _, f := range wgFiles {
		if f == "wg-infra.conf" {
			continue // синхронизируется выше через wg syncconf
		}
		name := strings.TrimSuffix(f, ".conf")
		// Адрес интерфейса не должен быть занят чужим устройством: wg-quick
		// успевает создать интерфейс и падает уже на «ip address add» с
		// «RTNETLINK answers: Address already in use». Проверяем заранее и
		// говорим, кто занял адрес, — иначе это выглядит как баг панели.
		fmt.Fprintf(&b, `addr=$(sed -n 's/^Address = //p' %[1]q | head -n1)
if [ -n "$addr" ]; then
  busy=$(ip -4 -o addr show 2>/dev/null | awk -v a="$addr" '$4 == a {print $2; exit}')
  if [ -n "$busy" ] && [ "$busy" != %[2]q ]; then
    echo "[revhub] адрес $addr (конфиг '%[1]s') уже занят интерфейсом $busy" >&2
    echo "[revhub] сними его: ip link del $busy — или задай инбаунду другую подсеть" >&2
    exit 1
  fi
fi
`, f, name)
		// wg-quick down может не снять интерфейс (нет секции PostDown, битый
		// файл): тогда up упадёт на «Address already in use». После down
		// проверяем и добиваем интерфейс руками.
		//
		// Юнит wg-quick@<имя> тоже может держать интерфейс (он enabled и мог
		// быть запущен systemd): пока он активен, наш up воюет с ним за адрес.
		// Гасим юнит, поднимаем сами, а если не вышло — печатаем состояние
		// сети, иначе причина снова будет невидимой.
		fmt.Fprintf(&b, "if ! cmp -s %q /etc/wireguard/%q || ! ip link show dev %q >/dev/null 2>&1; then\n"+
			"  if [ -d /run/systemd/system ]; then systemctl stop %q >/dev/null 2>&1 || true; fi\n"+
			"  if ip link show dev %q >/dev/null 2>&1; then\n"+
			"    wg-quick down %q >/dev/null 2>&1 || true\n"+
			"    if ip link show dev %q >/dev/null 2>&1; then ip link delete dev %q 2>/dev/null || true; fi\n"+
			"  fi\n"+
			"  if ! install -m 600 %q /etc/wireguard/%q 2>/dev/null; then\n"+
			"    echo \"[revhub] не записался /etc/wireguard/%q (только для чтения?)\" >&2\n"+
			"    exit 1\n"+
			"  fi\n"+
			// Ядро биндит UDP-порт WG-устройства в момент `ip link set up`:
			// если порт занят (свой wg0, другой интерфейс, служба), up падает
			// с «Address already in use», хотя адрес интерфейса свободен.
			"  lport=$(sed -n 's/^ListenPort = //p' /etc/wireguard/%q | head -n1)\n"+
			"  if [ -n \"$lport\" ] && ss -lunH \"sport = :$lport\" 2>/dev/null | grep -q .; then\n"+
			"    echo \"[revhub] UDP-порт $lport (конфиг '%q') уже слушает:\" >&2\n"+
			"    ss -lunp \"sport = :$lport\" >&2 || true\n"+
			"    echo \"[revhub] это другой туннель или служба — задай инбаунду свободный порт\" >&2\n"+
			"    exit 1\n"+
			"  fi\n"+
			"  if ! wg-quick up %q; then\n"+
			"    echo \"[revhub] интерфейс %q не поднялся; состояние сети:\" >&2\n"+
			"    ip -4 -o addr show >&2 || true\n"+
			"    ip route show table all 2>/dev/null | grep -F \"$(sed -n 's/^Address = //p' %q | head -n1 | cut -d/ -f1)\" >&2 || true\n"+
			"    wg show interfaces >&2 || true\n"+
			"    wg show all listen-port >&2 || true\n"+
			"    grep -n '^Address\\|^ListenPort' /etc/wireguard/%q >&2 || true\n"+
			"    exit 1\n"+
			"  fi\n"+
			"fi\n",
			f, f, name, "wg-quick@"+name+".service", name, name, name, name,
			f, f, f, f, f, name, name, f, f)
		// Интерфейс должен подниматься после перезагрузки: apply.sh запускается
		// один раз, а systemd поднимет wg-quick@<имя> сам.
		fmt.Fprintf(&b, "if [ -d /run/systemd/system ]; then systemctl enable %q >/dev/null 2>&1 || true; fi\n",
			"wg-quick@"+name+".service")
	}
	if len(kicks) > 0 {
		// Скрипт и таймер держат сессию без keepalive: пинг уходит только когда
		// сессии нет. Ставим их после подъёма интерфейсов и сразу дёргаем один раз.
		b.WriteString("install -d -m 700 /usr/local/libexec/revhub\n")
		for _, k := range kicks {
			fmt.Fprintf(&b, "install -m 700 %q /usr/local/libexec/revhub/%q 2>/dev/null || "+
				"echo \"[revhub] не записался скрипт %q (только для чтения?)\" >&2\n",
				"kick-"+k.Iface+".sh", "kick-"+k.Iface+".sh", "kick-"+k.Iface+".sh")
		}
		b.WriteString("if [ -d /run/systemd/system ]; then\n")
		for _, k := range kicks {
			fmt.Fprintf(&b, "  install -m 644 %q /etc/systemd/system/%q\n",
				"revhub-kick-"+k.Iface+".service", "revhub-kick-"+k.Iface+".service")
			fmt.Fprintf(&b, "  install -m 644 %q /etc/systemd/system/%q\n",
				"revhub-kick-"+k.Iface+".timer", "revhub-kick-"+k.Iface+".timer")
		}
		b.WriteString("  systemctl daemon-reload\n")
		for _, k := range kicks {
			fmt.Fprintf(&b, "  systemctl enable --now %q >/dev/null 2>&1 || true\n", "revhub-kick-"+k.Iface+".timer")
		}
		b.WriteString("fi\n")
		for _, k := range kicks {
			fmt.Fprintf(&b, "/usr/local/libexec/revhub/%q\n", "kick-"+k.Iface+".sh")
		}
	}
	if forward {
		// Рантайм-настройка PostUp живёт до перезагрузки; drop-in оставляет её
		// навсегда, иначе «туннель поднят, но не водит трафик» после ребута.
		b.WriteString(`install -d -m 755 /etc/sysctl.d 2>/dev/null || true
if printf '%s\n' 'net.ipv4.ip_forward=1' > /etc/sysctl.d/90-revhub.conf 2>/dev/null; then
  sysctl -q -p /etc/sysctl.d/90-revhub.conf 2>/dev/null || sysctl -q -w net.ipv4.ip_forward=1 || true
else
  echo "[revhub] не записался /etc/sysctl.d/90-revhub.conf (только для чтения?) — включаю форвардинг на сессию" >&2
  sysctl -q -w net.ipv4.ip_forward=1 2>/dev/null || echo "[revhub] ip_forward не включился — включи на узле сам" >&2
fi
`)
	}
	if dnsOn {
		// DNS — вспомогательная часть: если /etc/dnsmasq.d только для чтения
		// (бывает в контейнерах), применение сети не должно падать целиком.
		// Пишем предупреждение и продолжаем — сеть важнее зоны имён.
		b.WriteString(`
install -d -m 755 /etc/dnsmasq.d /etc/revhub 2>/dev/null || true
dns_changed=0
dns_ok=1
cmp -s dnsmasq-revhub.conf /etc/dnsmasq.d/revhub.conf 2>/dev/null || dns_changed=1
if ! install -m 644 dnsmasq-revhub.conf /etc/dnsmasq.d/revhub.conf 2>/dev/null; then
  dns_ok=0
  echo "[revhub] не записался /etc/dnsmasq.d/revhub.conf (файловая система только для чтения?) — зона DNS не обновится, сеть применяется дальше" >&2
fi
if ! install -m 644 dns-hosts /etc/revhub/dns-hosts 2>/dev/null; then
  dns_ok=0
  echo "[revhub] не записался /etc/revhub/dns-hosts — имена клиентов в DNS не обновятся" >&2
fi
if [ "$dns_ok" = 0 ]; then
  :
elif ! command -v dnsmasq >/dev/null 2>&1; then
  echo "[revhub] dnsmasq не установлен: зона DNS не поднята (apt install dnsmasq)" >&2
elif [ "$dns_changed" = 1 ]; then
  # Адреса, зона и порт читаются только при старте: SIGHUP перечитывает hosts.
  systemctl enable dnsmasq >/dev/null 2>&1 || true
  systemctl restart dnsmasq || echo "[revhub] dnsmasq не перезапустился, смотри journalctl -u dnsmasq" >&2
else
  systemctl reload dnsmasq >/dev/null 2>&1 || systemctl restart dnsmasq >/dev/null 2>&1 || true
fi
if [ "$dns_ok" = 0 ]; then
  echo "[revhub] сеть применена, но DNS — нет: общий статус применения — ошибка" >&2
  exit 1
fi
`)
	} else {
		// DNS выключили или перенесли на другой узел — убираем за собой.
		b.WriteString(`
if [ -f /etc/dnsmasq.d/revhub.conf ]; then
  rm -f /etc/dnsmasq.d/revhub.conf /etc/revhub/dns-hosts 2>/dev/null || true
  # try-restart трогает сервис, только если он запущен: на узле без DNS он не нужен
  systemctl reload dnsmasq >/dev/null 2>&1 || systemctl try-restart dnsmasq >/dev/null 2>&1 || true
  # Свой конфиг убрали; если чужих в /etc/dnsmasq.d нет, глушим сервис —
  # иначе dnsmasq продолжит слушать 0.0.0.0:53 без нашей зоны.
  if ! ls /etc/dnsmasq.d/*.conf >/dev/null 2>&1 && ! grep -qE '^[[:space:]]*[^#]' /etc/dnsmasq.conf 2>/dev/null; then
    systemctl disable --now dnsmasq >/dev/null 2>&1 || true
  fi
fi
`)
	}
	if !useXray {
		return b.String()
	}
	b.WriteString("\necho \"[revhub] применено. откат: ./rollback.sh\"\n")
	return b.String()
}

func rollbackScript(wgFiles []string, useXray bool, kicks []kick) string {
	var b strings.Builder
	b.WriteString("#!/usr/bin/env bash\nset -euo pipefail\ncd \"$(dirname \"$0\")\"\n")
	b.WriteString("XRAY_CONFIG=${XRAY_CONFIG:-/usr/local/etc/xray/config.json}\n")
	b.WriteString("STATE_DIR=${STATE_DIR:-/etc/revhub}\n")
	for _, k := range kicks {
		fmt.Fprintf(&b, "systemctl disable --now %q >/dev/null 2>&1 || true\n", "revhub-kick-"+k.Iface+".timer")
		fmt.Fprintf(&b, "rm -f /etc/systemd/system/%q /etc/systemd/system/%q /usr/local/libexec/revhub/%q\n",
			"revhub-kick-"+k.Iface+".service", "revhub-kick-"+k.Iface+".timer", "kick-"+k.Iface+".sh")
	}
	if len(kicks) > 0 {
		b.WriteString("if [ -d /run/systemd/system ]; then systemctl daemon-reload; fi\n")
	}
	for _, f := range wgFiles {
		name := strings.TrimSuffix(f, ".conf")
		fmt.Fprintf(&b, "wg-quick down %q 2>/dev/null || true\n", name)
	}
	if !useXray {
		return b.String()
	}
	b.WriteString(`
if [ -f "$STATE_DIR/last-good/xray.json" ]; then
  install -m 640 "$STATE_DIR/last-good/xray.json" "$XRAY_CONFIG"
  systemctl restart xray
  echo "[revhub] откат выполнен: предыдущий xray.json возвращён"
else
  echo "[revhub] предыдущего конфига нет: туннели сняты, ядро не тронуто"
fi
`)
	return b.String()
}

// WriteArtifacts пишет набор в каталог атомарно (через временный каталог).
func WriteArtifacts(dir string, files []File) (Manifest, error) {
	m := Manifest{Node: "", GeneratedAt: time.Now().UTC(), Files: map[string]string{}}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return m, err
	}
	tmp, err := os.MkdirTemp(dir, ".render-*")
	if err != nil {
		return m, err
	}
	defer os.RemoveAll(tmp)

	for _, f := range files {
		if err := os.WriteFile(filepath.Join(tmp, f.Name), []byte(f.Content), f.Mode); err != nil {
			return m, err
		}
		sum := sha256.Sum256([]byte(f.Content))
		m.Files[f.Name] = hex.EncodeToString(sum[:])
	}
	for name := range m.Files {
		if err := os.Rename(filepath.Join(tmp, name), filepath.Join(dir, name)); err != nil {
			return m, err
		}
	}
	return m, nil
}

func (m Manifest) JSON() []byte {
	b, _ := json.MarshalIndent(m, "", "  ")
	return append(b, '\n')
}
