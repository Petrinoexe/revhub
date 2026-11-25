package diag

import (
	"strings"
	"testing"

	"revhub/internal/model"
)

// fakeRunner отвечает на команды по подстроке-ключу: так проверка узла
// тестируется без systemd, ping и wg.
type fakeRunner struct {
	answers map[string]string
	seen    []string
}

func (f *fakeRunner) Run(cmd string) (string, error) {
	f.seen = append(f.seen, cmd)
	for key, out := range f.answers {
		if strings.Contains(cmd, key) {
			return out, nil
		}
	}
	return "", nil
}

func (f *fakeRunner) ran(sub string) bool {
	for _, c := range f.seen {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func TestTunnelRejectsShellInPingHost(t *testing.T) {
	r := &fakeRunner{}
	_, err := Tunnel(model.Demo(), "tun-eu", "1.1.1.1; touch /tmp/revhub-pwned", "hub", Runners{Local: r})
	if err == nil {
		t.Fatal("shell-строка принята как цель ping")
	}
	if len(r.seen) != 0 {
		t.Fatalf("до валидации цели уже выполнялись команды: %q", r.seen)
	}
}

func TestNodeDetectsUnappliedConfig(t *testing.T) {
	st := model.State{Version: model.StateVersion, Nodes: []model.Node{{ID: "hub"}},
		Inbounds: []model.Inbound{{ID: "in", NodeID: "hub", Tag: "vless-main", Kind: "vless",
			Listen: "0.0.0.0", Port: 443, Transport: "tcp", Security: "none", Enabled: true}},
		Clients: []model.Client{{ID: "c", Email: "a@b", UUID: model.GenUUID(), Enabled: true, Inbounds: []string{"in"}}}}
	r := &fakeRunner{answers: map[string]string{
		"systemctl is-active xray": "active\n",
		"sha256sum":                "deadbeef /usr/local/etc/xray/config.json\n",
		"ss -lntupH":               "tcp LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:((\"xray\",pid=1,fd=3))\n",
		"ufw status":               "Status: inactive\n",
	}}
	rep, err := Node(st, "hub", "hub", Runners{Local: r})
	if err != nil {
		t.Fatal(err)
	}
	var found *Item
	for i := range rep.Items {
		if strings.HasPrefix(rep.Items[i].Name, "конфиг ядра") {
			found = &rep.Items[i]
		}
	}
	if found == nil {
		t.Fatalf("нет проверки конфига: %+v", rep.Items)
	}
	if found.OK || found.Hint == "" {
		t.Fatalf("расхождение конфига должно быть ошибкой с подсказкой: %+v", *found)
	}
	if !strings.Contains(found.Hint, "применить") {
		t.Fatalf("подсказка не говорит применить конфиг: %q", found.Hint)
	}
	// Порт слушается — этот пункт должен быть зелёным.
	for _, it := range rep.Items {
		if it.Name == "порты слушаются" && !it.OK {
			t.Fatalf("порт 443 слушается, а проверка считает иначе: %+v", it)
		}
	}
}

func TestNodeReportsMissingListener(t *testing.T) {
	st := model.State{Version: model.StateVersion, Nodes: []model.Node{{ID: "hub"}},
		Inbounds: []model.Inbound{{ID: "in", NodeID: "hub", Tag: "vless-main", Kind: "vless",
			Port: 8443, Security: "none", Enabled: true}},
		Clients: []model.Client{{ID: "c", Email: "a@b", UUID: model.GenUUID(), Enabled: true, Inbounds: []string{"in"}}}}
	r := &fakeRunner{answers: map[string]string{"systemctl is-active xray": "active\n"}}
	rep, err := Node(st, "hub", "hub", Runners{Local: r})
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range rep.Items {
		if it.Name == "порты слушаются" {
			if it.OK || !strings.Contains(it.Out, "8443/tcp") {
				t.Fatalf("закрытый порт не показан: %+v", it)
			}
			return
		}
	}
	t.Fatalf("проверки портов нет: %+v", rep.Items)
}

// Узлу без ядра (чистый выход для WG) не нужны ни служба xray, ни сверка
// конфига — «inactive» и «файла нет» там норма, а не авария.
func TestNodeWithoutXraySkipsCoreChecks(t *testing.T) {
	st := model.State{Version: model.StateVersion,
		Nodes: []model.Node{{ID: "hub"}, {ID: "exit"}},
		Tunnels: []model.Tunnel{{ID: "tn", Name: "eu", Kind: model.TunnelWGReverse,
			FromNode: "hub", ToNode: "exit", Enabled: true, Subnet: "10.77.3.0/30", ListenPort: 51820}}}
	r := &fakeRunner{answers: map[string]string{"wg show interfaces": "wg-eu\n"}}
	rep, err := Node(st, "exit", "hub", Runners{Local: r, RemoteFor: func(string) (Runner, error) { return r, nil }})
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range rep.Items {
		if it.Name == "конфиг ядра на узле" {
			t.Fatalf("на узле без ядра сверка конфига не нужна: %+v", it)
		}
		if it.Name == "служба xray" && !it.OK {
			t.Fatalf("inactive xray на выходе — норма: %+v", it)
		}
	}
}

// `wg show <iface>` требует root: локально диагностика обязана идти через
// привилегированный помощник, иначе она врёт «интерфейс не поднят».
func TestNodeUsesPrivilegedWGOnLocalNode(t *testing.T) {
	st := model.State{Version: model.StateVersion,
		Nodes: []model.Node{{ID: "hub"}},
		Tunnels: []model.Tunnel{{ID: "tn", Name: "eu", Kind: model.TunnelWGReverse,
			FromNode: "hub", ToNode: "exit", Enabled: true, Subnet: "10.77.3.0/30", ListenPort: 51820}}}
	local := &fakeRunner{}
	var calls [][]string
	rs := Runners{Local: local, WG: func(args ...string) (string, error) {
		calls = append(calls, args)
		if len(args) == 2 && args[1] == "interfaces" {
			return "wg-eu\n", nil
		}
		return "key 1700000000\n", nil
	}}
	rep, err := Node(st, "hub", "hub", rs)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) == 0 {
		t.Fatal("wg вызывался не через помощника")
	}
	for _, it := range rep.Items {
		if it.Name == "интерфейсы WireGuard" && !it.OK {
			t.Fatalf("интерфейс есть, проверка не прошла: %+v", it)
		}
	}
}

// Порты для firewall: клиентские инбаунды и слушатели туннелей, без дублей.
func TestTunnelPingUsesInterfaceAndHost(t *testing.T) {
	st := model.State{Version: model.StateVersion,
		Nodes: []model.Node{{ID: "hub"}, {ID: "exit", PublicAddr: "203.0.113.9:443"}},
		Tunnels: []model.Tunnel{{ID: "t", Name: "eu", Kind: model.TunnelWGReverse,
			FromNode: "hub", ToNode: "exit", Enabled: true, Subnet: "10.77.1.0/30", ListenPort: 51820}}}
	r := &fakeRunner{answers: map[string]string{
		"latest-handshakes": "abc 1700000000\n",
		"ping -c 3":         "3 packets transmitted, 3 received, 0% packet loss, time 2003ms\n",
	}}
	rep, err := Tunnel(st, "t", "example.com", "hub", Runners{Local: r})
	if err != nil {
		t.Fatal(err)
	}
	if !r.ran("-I wg-eu 10.77.1.2") {
		t.Fatalf("нет пинга дальнего конца по интерфейсу: %v", r.seen)
	}
	if !r.ran("-I wg-eu example.com") {
		t.Fatalf("нет пинга внешнего хоста через туннель: %v", r.seen)
	}
	for _, it := range rep.Items {
		if !it.OK {
			t.Fatalf("проверка не прошла: %+v", it)
		}
	}
}

func TestPingItemParsesLoss(t *testing.T) {
	loss := &fakeRunner{answers: map[string]string{"ping": "3 packets transmitted, 0 received, 100% packet loss\n"}}
	it := pingItem(loss, "пинг", "ping -c 3 -I wg-x 1.1.1.1", "нет связи")
	if it.OK || it.Hint != "нет связи" {
		t.Fatalf("100%% потерь должно быть ошибкой: %+v", it)
	}
	noping := &fakeRunner{answers: map[string]string{"ping": "bash: ping: command not found\n"}}
	it = pingItem(noping, "пинг", "ping -c 3 1.1.1.1", "нет связи")
	if !it.OK || !it.Warn {
		t.Fatalf("отсутствие ping — предупреждение, не провал: %+v", it)
	}
}

func TestListeningMatchesProtoAndPort(t *testing.T) {
	ss := strings.Join([]string{
		"tcp   LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:((\"xray\"))",
		"udp   UNCONN 0 0 0.0.0.0:51820 0.0.0.0:* users:((\"xray\"))",
	}, "\n")
	if !listening(ss, "443", "tcp") {
		t.Fatal("tcp/443 не найден")
	}
	if !listening(ss, "51820", "udp") {
		t.Fatal("udp/51820 не найден")
	}
	if listening(ss, "443", "udp") {
		t.Fatal("tcp-порт 443 не должен считаться udp")
	}
	if listening(ss, "8443", "tcp") {
		t.Fatal("незанятый порт найден")
	}
}
