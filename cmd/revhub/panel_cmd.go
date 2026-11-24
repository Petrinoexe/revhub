package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"revhub/internal/model"
	"revhub/internal/store"
)

// cmdPanel — переключение адреса, на котором слушает панель, из CLI.
//
// Адрес живёт в состоянии (panel.listen), поэтому «переключить интерфейс» =
// записать новый адрес и перезапустить юнит. Панель в этот момент нельзя
// оставлять живой: она периодически пересохраняет состояние (статусы узлов) и
// затёрла бы правку — поэтому при активном юните сначала stop, потом запись,
// потом start.
func cmdPanel(args []string) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		// `revhub panel --state X` = показать: подкоманда не обязательна
		args = append([]string{"show"}, args...)
	}
	statePath := defaultStatePath()
	localNode := "node-1"
	restart := true
	dry := false
	portFlag := 0

	fs := flag.NewFlagSet("panel", flag.ExitOnError)
	fs.StringVar(&statePath, "state", statePath, "файл состояния")
	fs.StringVar(&localNode, "local-node", localNode, "id узла, на котором работает панель")
	fs.BoolVar(&restart, "restart", true, "перезапустить панель после смены адреса")
	fs.BoolVar(&dry, "dry-run", false, "только показать, что изменится")
	fs.IntVar(&portFlag, "port", 0, "порт панели (по умолчанию — как сейчас)")
	cmd := args[0]
	// Флаги разрешаем и после позиционного аргумента (`panel set wg --dry-run`):
	// flag.Parse останавливается на первом не-флаге, поэтому раскладываем вручную.
	var flags, rest []string
	tail := args[1:]
	for i := 0; i < len(tail); i++ {
		a := tail[i]
		if strings.HasPrefix(a, "-") && a != "-" {
			flags = append(flags, a)
			// у булевых флагов значения нет — не съедаем следующий аргумент
			if !strings.Contains(a, "=") && i+1 < len(tail) && !strings.HasPrefix(tail[i+1], "-") {
				switch a {
				case "-dry-run", "--dry-run", "-restart", "--restart":
				default:
					flags = append(flags, tail[i+1])
					i++
				}
			}
			continue
		}
		rest = append(rest, a)
	}
	fs.Parse(flags)

	switch cmd {
	case "show", "list", "status":
		panelShow(os.Stdout, statePath, localNode)
	case "set":
		if len(rest) != 1 {
			die("panel set: нужен один адрес\n  revhub panel set localhost | wg | wg:<тег> | <ip|host>[:порт]")
		}
		panelSet(statePath, localNode, rest[0], portFlag, restart, dry)
	case "localhost", "loopback":
		panelSet(statePath, localNode, "localhost", portFlag, restart, dry)
	case "wg":
		target := "wg"
		if len(rest) == 1 {
			target = "wg:" + rest[0]
		} else if len(rest) > 1 {
			die("panel wg: не больше одного тега инбаунда")
		}
		panelSet(statePath, localNode, target, portFlag, restart, dry)
	default:
		die("panel: неизвестная команда %q\n  revhub panel [show|list] | set <адрес> | localhost | wg [тег]", cmd)
	}
}

// defaultStatePath — каталог установки, если он есть, иначе файл в текущем
// каталоге (ручной запуск, отладка).
func defaultStatePath() string {
	if _, err := os.Stat("/etc/revhub/state.json"); err == nil {
		return "/etc/revhub/state.json"
	}
	return "state.json"
}

func panelShow(w io.Writer, statePath, localNode string) {
	st, err := store.Open(statePath)
	if err != nil {
		die("состояние %s: %v", statePath, err)
	}
	state := st.Snapshot()
	fmt.Fprintf(w, "панель слушает: %s\n", state.Panel.Addr())
	if state.Panel.LoopbackOnly() {
		fmt.Fprintln(w, "  только с этой машины (или через ssh-туннель)")
	} else {
		fmt.Fprintln(w, "  из сети WireGuard, из интернета недоступно")
	}
	fmt.Fprintf(w, "юнит: %s\n", panelUnitState())

	choices := panelChoices(state, localNode)
	if len(choices) == 0 {
		fmt.Fprintln(w, "вариантов нет: в состоянии этого узла нет ни одного WireGuard-инбаунда")
		return
	}
	fmt.Fprintln(w, "варианты:")
	for _, c := range choices {
		mark := " "
		if c.addr == state.Panel.Addr() {
			mark = "*"
		}
		live := ""
		if c.live {
			live = "  (интерфейс поднят)"
		}
		fmt.Fprintf(w, " %s %-52s %s%s\n", mark, c.addr, c.label, live)
	}
	fmt.Fprintln(w, "\nпереключить: revhub panel set wg | localhost | <ip:порт>")
}

type panelChoice struct {
	addr  string
	label string
	live  bool
}

// panelChoices — адреса, на которых панель имеет смысл держать: loopback и
// адреса WireGuard-интерфейсов этого узла. «live» — интерфейс уже в системе.
func panelChoices(st model.State, localNode string) []panelChoice {
	_, port, err := net.SplitHostPort(st.Panel.Addr())
	if err != nil {
		port = "2096"
	}
	out := []panelChoice{{
		addr:  net.JoinHostPort("127.0.0.1", port),
		label: "только эта машина",
	}}
	for _, in := range st.Inbounds {
		if !in.Enabled || in.Kind != model.InboundWireGuard || in.NodeID != localNode || in.WireGuard == nil {
			continue
		}
		addr := in.WireGuard.ServerAddress()
		if addr == "" {
			continue
		}
		out = append(out, panelChoice{
			addr:  net.JoinHostPort(addr, port),
			label: fmt.Sprintf("WireGuard %s (%s)", in.Tag, in.WireGuard.Subnet),
			live:  ifaceUp(in.WGInterface()),
		})
	}
	return out
}

func ifaceUp(name string) bool {
	if _, err := net.InterfaceByName(name); err == nil {
		return true
	}
	return false
}

// resolvePanelAddr превращает то, что набрал человек, в host:port.
//
//	localhost | loopback | 127.0.0.1  — только петля
//	wg | wg:<тег> | wg:<интерфейс>    — адрес WireGuard-интерфейса узла
//	<ip|host>[:порт]                  — как есть
func resolvePanelAddr(st model.State, localNode, target string, currentPort int) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", errors.New("пустой адрес")
	}
	if currentPort == 0 {
		currentPort = 2096
	}
	port := strconv.Itoa(currentPort)
	lower := strings.ToLower(target)

	switch {
	case lower == "localhost" || lower == "loopback" || lower == "127.0.0.1":
		return net.JoinHostPort("127.0.0.1", port), nil
	case lower == "wg" || strings.HasPrefix(lower, "wg:"):
		tag := strings.TrimPrefix(lower, "wg:")
		tag = strings.TrimPrefix(tag, ":")
		var tags []string
		for _, in := range st.Inbounds {
			if !in.Enabled || in.Kind != model.InboundWireGuard || in.NodeID != localNode || in.WireGuard == nil {
				continue
			}
			addr := in.WireGuard.ServerAddress()
			if addr == "" {
				continue
			}
			tags = append(tags, in.Tag)
			if tag == "" || strings.EqualFold(in.Tag, tag) || strings.EqualFold(in.WGInterface(), tag) {
				return net.JoinHostPort(addr, port), nil
			}
		}
		if tag == "" {
			return "", fmt.Errorf("на узле %s нет включённых WireGuard-инбаундов", localNode)
		}
		sort.Strings(tags)
		return "", fmt.Errorf("на узле %s нет WireGuard-инбаунда %q (есть: %s)", localNode, tag, strings.Join(tags, ", "))
	}

	// Голая метка инбаунда без префикса (`panel set wg-backup`) — тоже его адрес:
	// иначе она молча записалась бы как имя хоста.
	if !strings.ContainsAny(target, ".:") {
		for _, in := range st.Inbounds {
			if !in.Enabled || in.Kind != model.InboundWireGuard || in.NodeID != localNode || in.WireGuard == nil {
				continue
			}
			if strings.EqualFold(in.Tag, target) || strings.EqualFold(in.WGInterface(), target) {
				if addr := in.WireGuard.ServerAddress(); addr != "" {
					return net.JoinHostPort(addr, port), nil
				}
			}
		}
	}

	if host, p, err := net.SplitHostPort(target); err == nil {
		if n, err := strconv.Atoi(p); err != nil || n <= 0 || n > 65535 {
			return "", fmt.Errorf("некорректный порт %q", p)
		}
		return net.JoinHostPort(host, p), nil
	}
	return net.JoinHostPort(target, port), nil
}

func panelSet(statePath, localNode, target string, portFlag int, restart, dry bool) {
	st, err := store.Open(statePath)
	if err != nil {
		die("состояние %s: %v", statePath, err)
	}
	state := st.Snapshot()
	_, curPort, err := net.SplitHostPort(state.Panel.Addr())
	port := portFlag
	if port == 0 && err == nil {
		port, _ = strconv.Atoi(curPort)
	}
	addr, err := resolvePanelAddr(state, localNode, target, port)
	if err != nil {
		die("%v", err)
	}
	if addr == state.Panel.Addr() {
		fmt.Printf("панель уже слушает %s — ничего не меняю\n", addr)
		return
	}

	active := panelUnitActive()
	if active && !restart {
		fmt.Println("внимание: панель запущена и пересохранит состояние — правка потеряется")
	}
	if dry {
		fmt.Printf("было: %s\nстанет: %s\n", state.Panel.Addr(), addr)
		if active {
			fmt.Println("юнит будет остановлен, состояние записано, юнит запущен")
		}
		return
	}

	// Пока панель жива, писать в файл нельзя: монитор сохраняет состояние раз в
	// 20 с и перетрёт правку. Останавливаем юнит, пишем, запускаем.
	stopped := false
	if active {
		if os.Geteuid() != 0 {
			die("юнит revhub запущен: остановить его может только root\n  sudo %s panel set %s", selfPath(), target)
		}
		if out, err := exec.Command("systemctl", "stop", "revhub").CombinedOutput(); err != nil {
			die("systemctl stop revhub: %v: %s", err, strings.TrimSpace(string(out)))
		}
		stopped = true
	}

	if err := st.Patch(func(s *model.State) error {
		s.Panel = &model.PanelConfig{Listen: addr}
		return nil
	}); err != nil {
		if stopped {
			_ = exec.Command("systemctl", "start", "revhub").Run()
		}
		die("не сохранилось: %v", err)
	}
	fmt.Printf("адрес панели: %s → %s\n", state.Panel.Addr(), addr)

	if !stopped {
		fmt.Println("юнит revhub не запущен — запусти его сам: systemctl start revhub")
		return
	}
	if out, err := exec.Command("systemctl", "start", "revhub").CombinedOutput(); err != nil {
		die("адрес записан, но панель не запустилась: %v: %s\n  журнал: journalctl -u revhub -n 50",
			err, strings.TrimSpace(string(out)))
	}
	fmt.Printf("панель перезапущена: %s\n", addr)
}

// die печатает ошибку и выходит: CLI не должен молчать о том, что не сделал.
func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "revhub: "+format+"\n", a...)
	os.Exit(1)
}

func selfPath() string {
	if p, err := os.Executable(); err == nil {
		return p
	}
	return "revhub"
}

func panelUnitActive() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	return exec.Command("systemctl", "is-active", "--quiet", "revhub").Run() == nil
}

func panelUnitState() string {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return "systemctl нет: панель запускается вручную"
	}
	out, err := exec.Command("systemctl", "is-active", "revhub").Output()
	state := strings.TrimSpace(string(out))
	if err != nil && state == "" {
		return "не управляется systemd"
	}
	if state == "active" {
		return "работает (systemd)"
	}
	return state + " (systemd)"
}
