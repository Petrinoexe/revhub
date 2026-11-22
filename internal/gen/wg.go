package gen

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
		name := "wg-" + t.Name + ".conf"
		files = append(files, File{Name: name, Content: conf, Mode: 0o600})
		wgNames = append(wgNames, name)
	}
	sort.Strings(wgNames)

	files = append(files,
		File{Name: "apply.sh", Content: applyScript(nodeID, wgNames), Mode: 0o700},
		File{Name: "rollback.sh", Content: rollbackScript(wgNames), Mode: 0o700},
	)
	return files, nil
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

	var b strings.Builder
	fmt.Fprintf(&b, "# revhub: туннель %q, вид %s, узел %s\n", t.Name, t.Kind, nodeID)
	fmt.Fprintf(&b, "# направление трафика: %s → %s\n", t.FromNode, t.ToNode)
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "Address = %s/30\n", addr)
	fmt.Fprintf(&b, "PrivateKey = %s\n", pick(isFrom, t.FromKeyPriv, t.ToKeyPriv))
	b.WriteString("Table = off\n")
	fmt.Fprintf(&b, "MTU = %d\n", 1380)

	if nodeID == listener {
		fmt.Fprintf(&b, "ListenPort = %d\n", t.ListenPort)
	}
	if nodeID != listener {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", t.Keepalive)
	}

	if isFrom {
		// Единственная точка стыка двух плоскостей: метка → таблица → интерфейс.
		// Плюс host-route до дальнего конца в main: по нему панель ходит на
		// выходной по SSH через туннель, не задевая остальной трафик.
		fmt.Fprintf(&b, "PostUp = ip -4 route replace %s/32 dev %%i\n", toAddr)
		fmt.Fprintf(&b, "PostDown = ip -4 route del %s/32 dev %%i 2>/dev/null || true\n", toAddr)
		fmt.Fprintf(&b, "PostUp = ip rule add fwmark %d lookup %d 2>/dev/null || true\n", t.Mark, t.Mark)
		fmt.Fprintf(&b, "PostUp = ip -4 route replace default dev %%i table %d\n", t.Mark)
		fmt.Fprintf(&b, "PostDown = ip rule del fwmark %d lookup %d 2>/dev/null || true\n", t.Mark, t.Mark)
		fmt.Fprintf(&b, "PostDown = ip -4 route flush table %d 2>/dev/null || true\n", t.Mark)
	}
	if !isFrom && t.ForwardPolicy {
		fmt.Fprintf(&b, "PostUp = sysctl -q -w net.ipv4.ip_forward=1\n")
		fmt.Fprintf(&b, "PostUp = (nft add rule ip nat postrouting oifname %q ip saddr %s masquerade 2>/dev/null"+
			" || iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE) || true\n",
			t.EgressIface, t.Subnet, t.Subnet, t.EgressIface)
		fmt.Fprintf(&b, "PostDown = (nft delete rule ip nat postrouting handle $(nft -a list chain ip nat postrouting 2>/dev/null"+
			" | grep %q | head -1 | sed 's/.*handle //') 2>/dev/null"+
			" || iptables -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE) || true\n",
			t.EgressIface, t.Subnet, t.EgressIface)
	}

	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", otherPub)
	if nodeID == dialer {
		// Endpoint — адрес слушающей стороны. Порт берём из туннеля, а не из
		// public_addr узла: там лежит порт для клиентов (443), он тут не годится.
		host := hostOnly(mustNode(st, listener).PublicAddr)
		port := t.ListenPort
		if t.PublicPort > 0 {
			port = t.PublicPort
		}
		fmt.Fprintf(&b, "Endpoint = %s:%d\n", host, port)
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

// hostOnly отрезает порт от "host:port"; для IPv6 в скобках сохраняет адрес.
func hostOnly(addr string) string {
	if addr == "" {
		return "127.0.0.1"
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

func applyScript(nodeID string, wgFiles []string) string {
	var b strings.Builder
	b.WriteString("#!/usr/bin/env bash\n")
	b.WriteString("# Сгенерировано revhub. Порядок важен: сначала туннели, потом ядро.\n")
	b.WriteString("set -euo pipefail\ncd \"$(dirname \"$0\")\"\n")
	fmt.Fprintf(&b, "NODE=%q\n", nodeID)
	b.WriteString(`XRAY_BIN=${XRAY_BIN:-xray}
XRAY_CONFIG=${XRAY_CONFIG:-/usr/local/etc/xray/config.json}
STATE_DIR=${STATE_DIR:-/etc/revhub}

echo "[revhub] узел $NODE"

# 1. WireGuard: снять старое, поднять новое (PostUp делает правила и маршруты)
`)
	for _, f := range wgFiles {
		name := strings.TrimSuffix(f, ".conf")
		fmt.Fprintf(&b, "if [ -f %q ]; then wg-quick down %q 2>/dev/null || true; install -m 600 %q /etc/wireguard/%q; wg-quick up %q; fi\n",
			f, name, f, f, name)
	}
	b.WriteString(`
# 2. Ядро: проверка конфига ДО установки, иначе узел ляжет
"$XRAY_BIN" -test -c xray.json

# 3. Сохранить предыдущий рабочий конфиг и применить
install -d -m 750 "$STATE_DIR/last-good"
if [ -f "$XRAY_CONFIG" ]; then
  cp -a "$XRAY_CONFIG" "$STATE_DIR/last-good/xray.json"
fi
install -m 640 xray.json "$XRAY_CONFIG"
systemctl restart "${XRAY_BIN%% *}" 2>/dev/null || true
sleep 1
systemctl is-active --quiet "$(basename "$XRAY_BIN")" 2>/dev/null ||
  systemctl is-active --quiet xray ||
  echo "[revhub] внимание: юнит ядра не подтвердил active — проверь journalctl -u xray"

echo "[revhub] применено. откат: ./rollback.sh"
`)
	return b.String()
}

func rollbackScript(wgFiles []string) string {
	var b strings.Builder
	b.WriteString("#!/usr/bin/env bash\nset -euo pipefail\ncd \"$(dirname \"$0\")\"\n")
	b.WriteString("XRAY_CONFIG=${XRAY_CONFIG:-/usr/local/etc/xray/config.json}\n")
	b.WriteString("STATE_DIR=${STATE_DIR:-/etc/revhub}\n")
	for _, f := range wgFiles {
		name := strings.TrimSuffix(f, ".conf")
		fmt.Fprintf(&b, "wg-quick down %q 2>/dev/null || true\n", name)
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
