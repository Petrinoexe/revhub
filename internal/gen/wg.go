package gen

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
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

	var wgNames []string
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
	useXray := len(wgNames) == 0 || NeedsXray(st, nodeID)
	// Узел выпускает трафик туннеля в интернет — значит, ему нужен ip_forward
	// не только до перезагрузки: PostUp wg-quick выставляет его в рантайме, но
	// systemd-sysctl при загрузке может вернуть 0, и туннель «поднят, но не водит».
	forward := false
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
		fromAddr, toAddr, err := model.SubnetAddrs(t.Subnet)
		if err != nil {
			continue
		}
		peer := fromAddr
		if t.ListenerNode() == t.ToNode {
			peer = toAddr
		}
		kicks = append(kicks, kick{Iface: t.WGInterface(), Peer: peer})
	}

	files = append(files,
		// Обратный туннель открывает дозванивающаяся сторона. Слушатель не
		// может её разбудить: пока сессии нет, у него нет адреса пира. Значит,
		// будить должен сам дозванивающийся — скрипт и таймер ниже делают это
		// только когда сессии действительно нет (keepalive мы не держим).
		kickFiles(kicks)...,
	)
	files = append(files,
		File{Name: "apply.sh", Content: applyScript(wgNames, useXray, NodePorts(st, nodeID), forward, kicks), Mode: 0o700},
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
		if in.Enabled && in.NodeID == nodeID {
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

// WGConfig рендерит wg-quick конфиг для одного конца туннеля.
//
// Инвариант: Table = off всегда. Маршрутизацию в туннель делает только
// сторона From, через fwmark + отдельную таблицу; сторона To выпускает
// трафик наружу (при ForwardPolicy) и не трогает свои маршруты.
func WGConfig(st model.State, t model.Tunnel, nodeID string) (string, error) {
	if !t.Touches(nodeID) {
		return "", fmt.Errorf("узел %q не участвует в туннеле", nodeID)
	}
	fromAddr, toAddr, err := model.SubnetAddrs(t.Subnet)
	if err != nil {
		return "", err
	}
	listener, dialer := t.ListenerNode(), t.DialerNode()
	isFrom := nodeID == t.FromNode

	addr, otherPub := toAddr, t.FromKeyPub
	if isFrom {
		addr, otherPub = fromAddr, t.ToKeyPub
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
	fmt.Fprintf(&b, "Address = %s/30\n", addr)
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
		fmt.Fprintf(&b, "PostUp = ip -4 route replace %s/32 dev %%i\n", toAddr)
		fmt.Fprintf(&b, "PostDown = ip -4 route del %s/32 dev %%i 2>/dev/null || true\n", toAddr)
		fmt.Fprintf(&b, "PostUp = ip rule add fwmark %d lookup %d 2>/dev/null || true\n", t.Mark, t.Mark)
		fmt.Fprintf(&b, "PostUp = ip -4 route replace default dev %%i table %d\n", t.Mark)
		// Replies arrive on WireGuard, while the unmarked reverse path uses the WAN.
		b.WriteString("PostUp = printf '2\\n' > /proc/sys/net/ipv4/conf/%i/rp_filter\n")
		fmt.Fprintf(&b, "PostDown = ip rule del fwmark %d lookup %d 2>/dev/null || true\n", t.Mark, t.Mark)
		fmt.Fprintf(&b, "PostDown = ip -4 route flush table %d 2>/dev/null || true\n", t.Mark)
	}
	if !isFrom && t.ForwardPolicy {
		if err := writeNAT(&b, t, fromAddr); err != nil {
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
		fmt.Fprintf(&b, "AllowedIPs = %s/32\n", fromAddr)
	}
	return b.String(), nil
}

func mustNode(st model.State, id string) model.Node {
	n, _ := findNode(st, id)
	return n
}

func writeNAT(b *strings.Builder, t model.Tunnel, fromAddr string) error {
	sum := sha256.Sum256([]byte(t.WGInterface()))
	table := fmt.Sprintf("revhub_%x", sum[:6])
	selector := `iifname "%i" ip saddr ` + fromAddr + `/32 oifname != "%i"`
	// iptables POSTROUTING cannot match the input interface.
	legacy := "-s " + fromAddr + "/32 ! -o %i"
	if iface := t.EgressIface; iface != "" {
		if len(iface) > 15 || strings.ContainsFunc(iface, func(c rune) bool {
			return !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_=+.-", c))
		}) {
			return fmt.Errorf("некорректное имя выходного интерфейса %q", iface)
		}
		fmt.Fprintf(b, "PostUp = ip link show dev %q >/dev/null\n", iface)
		selector = `iifname "%i" ip saddr ` + fromAddr + "/32 oifname " + strconv.Quote(iface)
		legacy = "-s " + fromAddr + "/32 -o " + iface
	}
	b.WriteString("PostUp = sysctl -q -w net.ipv4.ip_forward=1\n")
	// Create a separate table so nftables works even on a fresh exit node.
	fmt.Fprintf(b, "PostUp = if command -v nft >/dev/null; then printf '%%s\\n' 'add table ip %s' 'add chain ip %s postrouting { type nat hook postrouting priority srcnat; }' 'add rule ip %s postrouting %s masquerade' | nft -f -; else iptables -t nat -A POSTROUTING %s -j MASQUERADE; fi\n",
		table, table, table, selector, legacy)
	fmt.Fprintf(b, "PostDown = if command -v nft >/dev/null; then nft delete table ip %s; else iptables -t nat -D POSTROUTING %s -j MASQUERADE; fi\n", table, legacy)
	return nil
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
	Iface string
	Peer  string
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
# пока не знает адреса пира. Поэтому при отсутствии/устаревании сессии шлём
# один пакет по туннелю — хендшейк уходит от нас к слушателю.
set -u
iface=%[1]s
peer=%[2]s
h=$(wg show "$iface" latest-handshakes 2>/dev/null | awk '{print $2}' | sort -n | tail -1)
now=$(date +%%s)
if [ -z "${h:-}" ] || [ "${h:-0}" -eq 0 ] || [ $((now-h)) -gt 150 ]; then
  ping -c1 -W1 -I "$iface" "$peer" >/dev/null 2>&1 || true
fi
`, k.Iface, k.Peer)
		out = append(out, File{Name: "kick-" + k.Iface + ".sh", Content: script, Mode: 0o755})
		out = append(out, File{Name: "revhub-kick-" + k.Iface + ".service",
			Content: fmt.Sprintf(`[Unit]
Description=revhub: сессия туннеля %s
After=wg-quick@%s.service

[Service]
Type=oneshot
ExecStart=/etc/revhub/kick-%s.sh
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

func applyScript(wgFiles []string, useXray bool, ports []string, forward bool, kicks []kick) string {
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
		b.WriteString(`XRAY_BIN=${XRAY_BIN:-xray}
XRAY_CONFIG=${XRAY_CONFIG:-/usr/local/etc/xray/config.json}
STATE_DIR=${STATE_DIR:-/etc/revhub}
"$XRAY_BIN" -test -c xray.json
`)
	}
	if len(wgFiles) > 0 {
		b.WriteString("install -d -m 700 /etc/wireguard\n")
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
`)
	}
	for _, f := range wgFiles {
		name := strings.TrimSuffix(f, ".conf")
		fmt.Fprintf(&b, "if ! cmp -s %q /etc/wireguard/%q || ! ip link show dev %q >/dev/null 2>&1; then\n  if ip link show dev %q >/dev/null 2>&1; then wg-quick down %q; fi\n  install -m 600 %q /etc/wireguard/%q\n  wg-quick up %q\nfi\n",
			f, f, name, name, name, f, f, name)
		// Интерфейс должен подниматься после перезагрузки: apply.sh запускается
		// один раз, а systemd поднимет wg-quick@<имя> сам.
		fmt.Fprintf(&b, "if [ -d /run/systemd/system ]; then systemctl enable %q >/dev/null 2>&1 || true; fi\n",
			"wg-quick@"+name+".service")
	}
	if len(kicks) > 0 {
		// Скрипт и таймер держат сессию без keepalive: пинг уходит только когда
		// сессии нет. Ставим их после подъёма интерфейсов и сразу дёргаем один раз.
		b.WriteString("install -d -m 755 /etc/revhub\n")
		for _, k := range kicks {
			fmt.Fprintf(&b, "install -m 755 %q /etc/revhub/%q\n",
				"kick-"+k.Iface+".sh", "kick-"+k.Iface+".sh")
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
			fmt.Fprintf(&b, "/etc/revhub/%q\n", "kick-"+k.Iface+".sh")
		}
	}
	if forward {
		// Рантайм-настройка PostUp живёт до перезагрузки; drop-in оставляет её
		// навсегда, иначе «туннель поднят, но не водит трафик» после ребута.
		b.WriteString(`install -d -m 755 /etc/sysctl.d
printf '%s\n' 'net.ipv4.ip_forward=1' > /etc/sysctl.d/90-revhub.conf
sysctl -q -p /etc/sysctl.d/90-revhub.conf 2>/dev/null || sysctl -q -w net.ipv4.ip_forward=1
`)
	}
	if !useXray {
		return b.String()
	}
	b.WriteString(`
install -d "$(dirname "$XRAY_CONFIG")"
install -d -m 750 "$STATE_DIR/last-good"
had_config=0
if [ -f "$XRAY_CONFIG" ]; then
  cp -a "$XRAY_CONFIG" "$STATE_DIR/last-good/xray.json"
  had_config=1
fi
candidate=$(mktemp "${XRAY_CONFIG}.revhub.XXXXXX")
trap 'rm -f -- "$candidate"' EXIT
install -m 640 xray.json "$candidate"
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

echo "[revhub] применено. откат: ./rollback.sh"
`)
	return b.String()
}

func rollbackScript(wgFiles []string, useXray bool, kicks []kick) string {
	var b strings.Builder
	b.WriteString("#!/usr/bin/env bash\nset -euo pipefail\ncd \"$(dirname \"$0\")\"\n")
	b.WriteString("XRAY_CONFIG=${XRAY_CONFIG:-/usr/local/etc/xray/config.json}\n")
	b.WriteString("STATE_DIR=${STATE_DIR:-/etc/revhub}\n")
	for _, k := range kicks {
		fmt.Fprintf(&b, "systemctl disable --now %q >/dev/null 2>&1 || true\n", "revhub-kick-"+k.Iface+".timer")
		fmt.Fprintf(&b, "rm -f /etc/systemd/system/%q /etc/systemd/system/%q /etc/revhub/%q\n",
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
