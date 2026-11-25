// Package diag — проверки «почему не работает»: состояние ядра и портов на
// узле, а также пинг по туннелю до обоих концов и до внешнего хоста.
//
// Проверки выполняются на самом узле (локально или по SSH) и возвращают
// человекочитаемые пункты: что спрашивали, что получили, что с этим делать.
package diag

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"revhub/internal/gen"
	"revhub/internal/model"
)

// Runner — минимальный доступ к машине: выполнить команду.
type Runner interface {
	Run(cmd string) (string, error)
}

// Local выполняет команды на этой машине.
type Local struct{ Timeout time.Duration }

func (l Local) Run(cmd string) (string, error) {
	timeout := l.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "bash", "-c", cmd).CombinedOutput()
	return string(out), err
}

// Item — одна проверка.
type Item struct {
	Name string `json:"name"`
	Cmd  string `json:"cmd,omitempty"`
	OK   bool   `json:"ok"`
	Warn bool   `json:"warn,omitempty"`
	Out  string `json:"out,omitempty"`
	Hint string `json:"hint,omitempty"`
}

func ok(name, out string) Item { return Item{Name: name, OK: true, Out: short(out)} }
func bad(name, out, hint string) Item {
	return Item{Name: name, OK: false, Out: short(out), Hint: hint}
}
func warn(name, out, hint string) Item {
	return Item{Name: name, OK: true, Warn: true, Out: short(out), Hint: hint}
}

func short(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 1200 {
		return s[:1200] + "…"
	}
	return s
}

// hashHead — первые 12 символов суммы: sha256sum на узле может вернуть что
// угодно (чужой файл, баннер), поэтому режем безопасно.
func hashHead(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}

// Report — результат проверки.
type Report struct {
	NodeID string `json:"node_id,omitempty"`
	Tunnel string `json:"tunnel_id,omitempty"`
	Local  bool   `json:"local"`
	Items  []Item `json:"items"`
}

func (r Report) Failed() int {
	n := 0
	for _, it := range r.Items {
		if !it.OK {
			n++
		}
	}
	return n
}

// Runners — как добраться до узлов. RemoteFor открывает соединение к чужому
// узлу (SSH с сохранённым секретом); nil — удалённые проверки недоступны.
type Runners struct {
	Local     Runner
	RemoteFor func(nodeID string) (Runner, error)
	// ConfigPath — файл конфига ядра на узле. Пусто = боевой путь установщика.
	ConfigPath string
	// WG выполняет `wg ...` на локальном узле от root (через sudo). Без него
	// `wg show <iface>` из-под панели отвечает «Operation not permitted».
	WG func(args ...string) (string, error)
}

// runWG выполняет wg-команду: на локальном узле через привилегированный
// помощник, на удалённом — обычным SSH-shell (там мы root).
func (r Runners) runWG(run Runner, isLocal bool, args ...string) string {
	if isLocal && r.WG != nil {
		out, _ := r.WG(args...)
		return out
	}
	out, _ := run.Run("wg " + strings.Join(args, " "))
	return out
}

func (r Runners) configPath() string {
	if r.ConfigPath != "" {
		return r.ConfigPath
	}
	return "/usr/local/etc/xray/config.json"
}

func (r Runners) pick(nodeID, localNode string) (Runner, bool, error) {
	if nodeID == localNode {
		if r.Local == nil {
			return Local{}, true, nil
		}
		return r.Local, true, nil
	}
	if r.RemoteFor == nil {
		return nil, false, fmt.Errorf("узел %q не локальный, а SSH-доступ не настроен", nodeID)
	}
	run, err := r.RemoteFor(nodeID)
	if err != nil {
		return nil, false, err
	}
	return run, false, nil
}

// Node проверяет узел: работает ли ядро, тот ли конфиг применён, слушаются ли
// порты, что с firewall и WireGuard.
func Node(st model.State, nodeID, localNode string, rs Runners) (Report, error) {
	r, isLocal, err := rs.pick(nodeID, localNode)
	if err != nil {
		return Report{NodeID: nodeID, Local: isLocal}, err
	}
	rep := Report{NodeID: nodeID, Local: isLocal}

	// На узле, которому ядро не нужно (чистый выход для WG-туннеля), проверять
	// его бессмысленно: «inactive» там — норма, а не авария.
	needXray := gen.NeedsXray(st, nodeID)
	if needXray {
		if out, err := r.Run("systemctl is-active xray 2>/dev/null || true"); err != nil || strings.TrimSpace(out) != "active" {
			rep.Items = append(rep.Items, bad("служба xray", strings.TrimSpace(out),
				"ядро не запущено: systemctl status xray; journalctl -u xray -n 50"))
		} else {
			rep.Items = append(rep.Items, ok("служба xray", "active"))
		}
	} else {
		rep.Items = append(rep.Items, ok("служба xray", "на этом узле не нужна (только WireGuard)"))
	}

	// Ключевая проверка: лежит ли на узле ровно тот конфиг, который панель
	// только что сгенерировала. Расхождение = «настройки не применены».
	// Узлу без ядра этот пункт не нужен вовсе.
	if needXray {
		files, aerr := gen.Artifacts(st, nodeID)
		switch {
		case aerr != nil:
			// Модель не рендерится сама по себе (например, битые ключи WG):
			// молчать нельзя, иначе проверка выглядит успешной.
			rep.Items = append(rep.Items, bad("конфиг ядра на узле",
				"панель не смогла собрать конфиг: "+aerr.Error(),
				"исправь ошибку в состоянии — без валидного конфига применять нечего"))
		default:
			want := ""
			for _, f := range files {
				if f.Name == "xray.json" {
					sum := sha256.Sum256([]byte(f.Content))
					want = hex.EncodeToString(sum[:])
				}
			}
			out, _ := r.Run("sha256sum " + rs.configPath() + " 2>/dev/null || true")
			got := ""
			if f := strings.Fields(out); len(f) > 0 {
				got = f[0]
			}
			switch {
			case got == "":
				rep.Items = append(rep.Items, bad("конфиг ядра на узле", "не читается (нет файла или прав)",
					"конфиг не применялся: нажми «применить» на узле; панель читает его через группу"))
			case want != "" && got == want:
				rep.Items = append(rep.Items, ok("конфиг ядра на узле", "совпадает с панелью"))
			default:
				rep.Items = append(rep.Items, bad("конфиг ядра на узле", "sha256 "+hashHead(got)+" ≠ "+hashHead(want),
					"на узле старый конфиг: нажми «применить» на этом узле"))
			}
		}
	}

	// Слушающиеся порты: инбаунды и слушатели туннелей.
	ports := gen.NodePorts(st, nodeID)
	if len(ports) > 0 {
		out, _ := r.Run("ss -lntupH 2>/dev/null")
		var missing []string
		for _, spec := range ports {
			port, proto, _ := strings.Cut(spec, "/")
			if !listening(out, port, proto) {
				missing = append(missing, spec)
			}
		}
		if len(missing) == 0 {
			rep.Items = append(rep.Items, ok("порты слушаются", strings.Join(ports, " ")))
		} else {
			rep.Items = append(rep.Items, bad("порты слушаются", "нет: "+strings.Join(missing, " "),
				"портов не слышно: проверь, что инбаунд включён и конфиг применён"))
		}
	}

	// Firewall: закрытый порт снаружи выглядит как «клиент не подключается».
	if out, _ := r.Run("command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null || true"); strings.TrimSpace(out) != "" {
		active := strings.Contains(strings.ToLower(out), "status: active")
		if active && len(ports) > 0 {
			var closed []string
			for _, spec := range ports {
				port, _, _ := strings.Cut(spec, "/")
				if !strings.Contains(out, port+"/") && !strings.Contains(out, port+" ") {
					closed = append(closed, spec)
				}
			}
			if len(closed) > 0 {
				rep.Items = append(rep.Items, warn("firewall", "ufw active, не видно правил для "+strings.Join(closed, " "),
					"применение конфигурации открывает порты само; если правило не появилось — добавь вручную: ufw allow <порт>"+
						"/<tcp|udp>"))
			} else {
				rep.Items = append(rep.Items, ok("firewall", "ufw active, порты разрешены"))
			}
		} else {
			rep.Items = append(rep.Items, ok("firewall", "ufw не активен"))
		}
	}

	// WireGuard-интерфейсы и рукопожатия.
	var wgIfaces []string
	for _, t := range st.Tunnels {
		if t.Enabled && t.Touches(nodeID) && (t.Kind == model.TunnelWG || t.Kind == model.TunnelWGReverse) {
			wgIfaces = append(wgIfaces, t.WGInterface())
		}
	}
	if len(wgIfaces) > 0 {
		out := rs.runWG(r, isLocal, "show", "interfaces")
		up := strings.Fields(out)
		var missing []string
		for _, iface := range wgIfaces {
			if !containsStr(up, iface) {
				missing = append(missing, iface)
			}
		}
		if len(missing) > 0 {
			rep.Items = append(rep.Items, bad("интерфейсы WireGuard", "нет: "+strings.Join(missing, " "),
				"интерфейс не поднят: wg-quick up <имя> или применённый конфиг неверен"))
		} else {
			rep.Items = append(rep.Items, ok("интерфейсы WireGuard", strings.Join(wgIfaces, " ")))
		}
	}

	// Ошибки ядра: самая частая причина «инбаунд есть, но не отвечает».
	if out, _ := r.Run("journalctl -u xray -n 40 --no-pager 2>/dev/null || true"); strings.TrimSpace(out) != "" {
		low := strings.ToLower(out)
		if strings.Contains(low, "failed to") || strings.Contains(low, "error") || strings.Contains(low, "panic") {
			rep.Items = append(rep.Items, warn("журнал xray", out,
				"в журнале есть ошибки: скорее всего не читается сертификат или занят порт"))
		} else {
			rep.Items = append(rep.Items, ok("журнал xray", "ошибок не видно"))
		}
	}
	return rep, nil
}

func containsStr(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// listening ищет порт в выводе `ss -lntupH` с учётом протокола.
func listening(ss, port, proto string) bool {
	wantUDP := proto == "udp"
	for _, line := range strings.Split(ss, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		isUDP := f[0] == "udp" || strings.HasPrefix(f[0], "udp")
		if isUDP != wantUDP {
			continue
		}
		if strings.HasSuffix(f[4], ":"+port) {
			return true
		}
	}
	return false
}

// Tunnel проверяет связь по туннелю: рукопожатие WireGuard, пинг до дальнего
// конца по самому интерфейсу и, если задан host, пинг внешнего адреса через
// выходной узел.
func Tunnel(st model.State, tunnelID, host, localNode string, rs Runners) (Report, error) {
	var t model.Tunnel
	for _, x := range st.Tunnels {
		if x.ID == tunnelID {
			t = x
		}
	}
	if t.ID == "" {
		return Report{}, fmt.Errorf("туннель %q не найден", tunnelID)
	}
	from, fromLocal, err := rs.pick(t.FromNode, localNode)
	if err != nil {
		return Report{}, err
	}
	rep := Report{Tunnel: t.ID, NodeID: t.FromNode, Local: fromLocal}

	if t.Kind == model.TunnelVLESS {
		return vlessCheck(st, t, from, rep)
	}

	_, toAddr, err := t.Addrs()
	if err != nil {
		return rep, err
	}
	iface := t.WGInterface()

	if out := rs.runWG(from, fromLocal, "show", iface, "latest-handshakes"); strings.TrimSpace(out) == "" {
		rep.Items = append(rep.Items, bad("рукопожатие WireGuard", "нет данных: интерфейс "+iface+" не поднят",
			"применить конфигурацию на обоих узлах и проверить, что UDP-порт слушается"))
	} else {
		rep.Items = append(rep.Items, handshakeItem("рукопожатие WireGuard", out))
	}

	// Пинг по самому туннелю: пакет уходит в интерфейс, ответ приходит обратно.
	rep.Items = append(rep.Items, pingItem(from, "пинг дальнего конца по туннелю",
		fmt.Sprintf("ping -c 3 -W 2 -I %s %s", iface, toAddr), "туннель не пропускает даже ICMP между концами"))

	// Пинг «в мир» через выходной узел: проверяет NAT и forwarding на To.
	target := strings.TrimSpace(host)
	if target == "" {
		target = "1.1.1.1"
	}
	if net.ParseIP(target) == nil && strings.Contains(target, "/") {
		target = "1.1.1.1"
	}
	rep.Items = append(rep.Items, pingItem(from, "пинг "+target+" через выходной узел",
		fmt.Sprintf("ping -c 3 -W 2 -I %s %s", iface, target),
		"туннель жив, но выходной узел не выпускает трафик: проверь NAT и ip_forward на нём"))
	return rep, nil
}

func vlessCheck(st model.State, t model.Tunnel, from Runner, rep Report) (Report, error) {
	var to model.Node
	for _, n := range st.Nodes {
		if n.ID == t.ToNode {
			to = n
		}
	}
	port := t.ListenPortT
	host := hostOnly(to.PublicAddr)
	if host == "" {
		rep.Items = append(rep.Items, bad("адрес приёмной стороны", "не задан",
			"укажи public_addr у узла-приёмника"))
		return rep, nil
	}
	// Явные маркеры: по слову «open» в чужом выводе судить нельзя.
	cmd := fmt.Sprintf("timeout 5 bash -c 'cat < /dev/null > /dev/tcp/%s/%d' "+
		"&& echo __REVHUB_TCP_OPEN__ || echo __REVHUB_TCP_CLOSED__", host, port)
	out, _ := from.Run(cmd)
	display := strings.NewReplacer("__REVHUB_TCP_OPEN__", "соединение установлено",
		"__REVHUB_TCP_CLOSED__", "соединения нет").Replace(strings.TrimSpace(out))
	if strings.Contains(out, "__REVHUB_TCP_OPEN__") {
		rep.Items = append(rep.Items, ok("TCP до приёмной стороны", host+":"+strconv.Itoa(port)+" открыт"))
	} else {
		rep.Items = append(rep.Items, bad("TCP до приёмной стороны", display,
			"VLESS-туннель не принимает: проверь порт, сертификат и firewall на приёмной стороне"))
	}
	if t.Security == "tls" || t.Security == "reality" {
		rep.Items = append(rep.Items, ok("TLS", t.Security+" / SNI "+t.SNI))
	}
	rep.Items = append(rep.Items, Item{Name: "пинг", OK: true, Warn: true,
		Out:  "для VLESS пинг по туннелю не делается: это TCP-поток",
		Hint: "проверяй TCP-соединение выше или реальным клиентом"})
	return rep, nil
}

// pingItem выполняет пинг и трактует результат по числу принятых пакетов.
func pingItem(r Runner, name, cmd, hint string) Item {
	out, _ := r.Run(cmd + " 2>&1 || true")
	it := Item{Name: name, Cmd: cmd, Out: short(out)}
	if strings.Contains(out, "not known") || strings.Contains(out, "not found") {
		it.Warn = true
		it.OK = true
		it.Hint = "на узле нет ping (iputils-ping): поставь пакет, чтобы проверка работала"
		return it
	}
	recv := 0
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(strings.ToLower(line))
		idx := -1
		for i, w := range f {
			// в выводе iputils слово идёт как «3 received,» — снимаем запятую
			if strings.Trim(w, ",.;:") == "received" {
				idx = i
			}
		}
		if idx < 1 {
			continue
		}
		if v, err := strconv.Atoi(strings.Trim(f[idx-1], ",.;:")); err == nil {
			recv = v
		}
	}
	switch {
	case recv > 0:
		it.OK = true
	case strings.Contains(out, "Operation not permitted"):
		it.Warn, it.OK = true, true
		it.Hint = "нужны права на ping (CAP_NET_RAW): поставь iputils-ping или запусти проверку от root"
	default:
		it.OK = false
		it.Hint = hint
	}
	return it
}

func handshakeItem(name, out string) Item {
	newest := int64(0)
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		ts, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			continue
		}
		if ts > newest {
			newest = ts
		}
	}
	if newest == 0 {
		return bad(name, "рукопожатий не было",
			"ключи не совпали или порт закрыт: сверь public key на обеих сторонах")
	}
	age := time.Now().Unix() - newest
	return ok(name, fmt.Sprintf("последнее %d с назад", age))
}

func hostOnly(addr string) string {
	if addr == "" {
		return ""
	}
	if i := strings.LastIndex(addr, ":"); i > 0 && !strings.Contains(addr[i+1:], ":") {
		return addr[:i]
	}
	return addr
}
