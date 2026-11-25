package gen

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"revhub/internal/model"
)

func TestExpiredVLESSClientExcludedFromServer(t *testing.T) {
	st := model.Demo()
	st.Clients[0].ExpiresAt = "2000-01-01T00:00:00Z"
	raw, err := XrayJSON(st, "hub")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	for _, item := range cfg["inbounds"].([]any) {
		in := item.(map[string]any)
		if in["tag"] != "hub-reality" {
			continue
		}
		clients := in["settings"].(map[string]any)["clients"].([]any)
		if len(clients) != 0 {
			t.Fatalf("истёкший UUID остался на сервере: %v", clients)
		}
		return
	}
	t.Fatal("нет клиентского инбаунда")
}

func TestHubConfig(t *testing.T) {
	st := model.Demo()
	raw, err := XrayJSON(st, "hub")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("конфиг не JSON: %v", err)
	}

	outbounds := cfg["outbounds"].([]any)
	var tun map[string]any
	for _, o := range outbounds {
		m := o.(map[string]any)
		if m["tag"] == "tun:eu" {
			tun = m
		}
	}
	if tun == nil {
		t.Fatal("нет исходящего tun:eu — трафик некуда девать")
	}
	if tun["protocol"] != "freedom" {
		t.Errorf("исходящий туннеля должен быть freedom, получено %v", tun["protocol"])
	}
	ss := tun["streamSettings"].(map[string]any)["sockopt"].(map[string]any)
	if got := ss["mark"].(float64); got != 100 {
		t.Errorf("mark = %v, ожидалось 100", got)
	}

	rules := cfg["routing"].(map[string]any)["rules"].([]any)
	if got := rules[0].(map[string]any)["outboundTag"]; got != "api" {
		t.Errorf("первое правило должно быть api, получено %v", got)
	}
	last := rules[len(rules)-1].(map[string]any)
	if last["outboundTag"] != "tun:eu" {
		t.Errorf("последнее правило — пользовательский catch-all tun:eu, получено %v", last["outboundTag"])
	}

	inbounds := cfg["inbounds"].([]any)
	var clIn map[string]any
	for _, i := range inbounds {
		m := i.(map[string]any)
		if m["tag"] == "hub-reality" {
			clIn = m
		}
	}
	if clIn == nil {
		t.Fatal("нет клиентского инбаунда hub-reality")
	}
	clients := clIn["settings"].(map[string]any)["clients"].([]any)
	if len(clients) != 1 {
		t.Fatalf("ожидался 1 клиент, получено %d", len(clients))
	}
	if clients[0].(map[string]any)["email"] != "alice@revhub" {
		t.Errorf("email клиента потерялся: %v", clients[0])
	}
}

func TestExitConfigHasNoTunnelObjects(t *testing.T) {
	st := model.Demo()
	raw, err := XrayJSON(st, "exit-eu")
	if err != nil {
		t.Fatal(err)
	}
	// На выходном нет ни клиентского инбаунда, ни исходящего туннеля:
	// трафик приходит ядерным WG, а не через xray.
	if strings.Contains(string(raw), "tun:eu") {
		t.Error("на выходном не должно быть объектов туннеля в xray")
	}
	if strings.Contains(string(raw), "hub-reality") {
		t.Error("клиентский инбаунд хаба не должен попадать на выходной")
	}
}

func TestWGReverseSides(t *testing.T) {
	st := model.Demo()
	tun := st.Tunnels[0]

	hubConf, err := WGConfig(st, tun, "hub")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Table = off",
		"ListenPort = 51820",
		"Address = 10.88.0.200/32", // хаб в общей сети
		"PostUp = ip -4 route replace 10.88.0.250/32 dev %i", // маршрут для SSH через туннель
		"PostUp = ip rule add fwmark 100 lookup 100",
		"ip -4 route replace default dev %i table 100",
		"/proc/sys/net/ipv4/conf/%i/rp_filter",
		"AllowedIPs = 0.0.0.0/0",
	} {
		if !strings.Contains(hubConf, want) {
			t.Errorf("в конфиге хаба нет %q\n---\n%s", want, hubConf)
		}
	}
	if strings.Contains(hubConf, "Endpoint =") {
		t.Error("хаб — слушающая сторона, Endpoint ему не нужен")
	}

	exitConf, err := WGConfig(st, tun, "exit-eu")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Address = 10.88.0.250/32", // выход — адрес в общей сети
		"PersistentKeepalive = 25",
		"Endpoint = hub.example.com:51820",
		"ip_forward=1",
		"masquerade",
	} {
		if !strings.Contains(exitConf, want) {
			t.Errorf("в конфиге выходного нет %q\n---\n%s", want, exitConf)
		}
	}
	if strings.Contains(exitConf, "ip rule add fwmark") {
		t.Error("выходной не должен ставить метки: он не источник трафика")
	}
	peerSection := strings.SplitN(exitConf, "[Peer]\n", 2)
	if len(peerSection) != 2 || !strings.Contains(peerSection[1], "PersistentKeepalive = 25\n") || strings.Contains(peerSection[0], "PersistentKeepalive") {
		t.Fatal("PersistentKeepalive must be in [Peer], where wg-quick expects it")
	}
}

func TestForwardWGListenerIsExit(t *testing.T) {
	st := model.Demo()
	st.Tunnels[0].Kind = model.TunnelWG // прямой: слушает выходной
	hubConf, err := WGConfig(st, st.Tunnels[0], "hub")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(hubConf, "Endpoint = eu.example.com:51820") {
		t.Error("при kind=wg хаб должен дозваниваться на выходной")
	}
	if strings.Contains(hubConf, "ListenPort") {
		t.Error("при kind=wg хаб не слушает")
	}
}

func TestArtifactsSet(t *testing.T) {
	st := model.Demo()
	files, err := Artifacts(st, "hub")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, f := range files {
		names[f.Name] = true
		if f.Content == "" {
			t.Errorf("%s пустой", f.Name)
		}
	}
	for _, want := range []string{"xray.json", "wg-eu.conf", "apply.sh", "rollback.sh"} {
		if !names[want] {
			t.Errorf("нет артефакта %s", want)
		}
	}
}

// Без keepalive обратный туннель будит только дозванивающийся узел: скрипт
// шлёт один пакет при отсутствии сессии, таймер повторяет это раз в минуту.
func TestDialerGetsKickInsteadOfKeepalive(t *testing.T) {
	var st model.State
	st.Nodes = []model.Node{{ID: "hub", PublicAddr: "194.67.203.189:65423"}, {ID: "exit", PublicAddr: "5.180.31.201:443"}}
	st.Tunnels = []model.Tunnel{{ID: "tn", Name: "eu", Kind: model.TunnelWGReverse,
		FromNode: "hub", ToNode: "exit", Enabled: true, Subnet: "10.77.3.0/30",
		ListenPort: 51820, ForwardPolicy: true,
		FromKeyPriv: zeroKey, FromKeyPub: zeroKey, ToKeyPriv: zeroKey, ToKeyPub: zeroKey}}

	files, err := Artifacts(st, "exit")
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]File{}
	for _, f := range files {
		byName[f.Name] = f
	}
	kick, ok := byName["kick-wg-eu.sh"]
	if !ok {
		t.Fatalf("нет скрипта раскачки, есть: %v", keysOf(byName))
	}
	// Пир — слушающая сторона (хаб), её адрес в подсети: 10.77.3.1.
	if !strings.Contains(kick.Content, "peer_ip=10.77.3.1") || !strings.Contains(kick.Content, "iface=wg-eu") {
		t.Errorf("скрипт раскачки смотрит не туда:\n%s", kick.Content)
	}
	// Раскачка не должна зависеть от ping/curl: на свежем узле их может не быть.
	// Ненадолго включаем keepalive — WireGuard сам шлёт пакет и хендшейк уходит
	// от дозванивающейся стороны к слушателю.
	if !strings.Contains(kick.Content, `persistent-keepalive 1`) ||
		!strings.Contains(kick.Content, `persistent-keepalive off`) {
		t.Errorf("раскачка должна делаться через wg:\n%s", kick.Content)
	}
	if strings.Contains(kick.Content, "ping ") {
		t.Errorf("раскачка не должна зависеть от ping:\n%s", kick.Content)
	}
	if !strings.Contains(kick.Content, "latest-handshakes") {
		t.Error("скрипт должен проверять наличие сессии, а не молотить пингом всегда")
	}
	if _, ok := byName["revhub-kick-wg-eu.timer"]; !ok {
		t.Error("нет таймера, сессия не восстановится сама после перезагрузки хаба")
	}
	if !strings.Contains(byName["apply.sh"].Content, `systemctl enable --now "revhub-kick-wg-eu.timer"`) {
		t.Error("apply.sh не включает таймер")
	}
	if !strings.Contains(byName["apply.sh"].Content, `/usr/local/libexec/revhub/"kick-wg-eu.sh"`) {
		t.Error("apply.sh не дёргает раскачку из root-owned каталога")
	}
	if !strings.Contains(byName["revhub-kick-wg-eu.service"].Content, "ExecStart=/usr/local/libexec/revhub/kick-wg-eu.sh") {
		t.Error("root-таймер ссылается на изменяемый панелью скрипт")
	}
	// На слушающей стороне раскачки быть не должно — она ничего не дозванивает.
	hubFiles, err := Artifacts(st, "hub")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range hubFiles {
		if strings.HasPrefix(f.Name, "kick-") {
			t.Errorf("хабу раскачка не нужна: %s", f.Name)
		}
	}
	// С явным keepalive раскачка не нужна никому.
	st.Tunnels[0].Keepalive = 25
	files, err = Artifacts(st, "exit")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasPrefix(f.Name, "kick-") {
			t.Errorf("при keepalive раскачка лишняя: %s", f.Name)
		}
	}
}

func keysOf(m map[string]File) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Удалённый из панели туннель оставляет живой интерфейс с тем же адресом и
// меткой — новый туннель падает на «Address already in use». apply.sh обязан
// снять наши устаревшие конфиги, но не трогать чужие (ручной wg0).
func TestApplyScriptRemovesStaleRevhubInterfaces(t *testing.T) {
	var st model.State
	st.Nodes = []model.Node{{ID: "hub", PublicAddr: "194.67.203.189:65423"}, {ID: "exit", PublicAddr: "5.180.31.201:443"}}
	st.Tunnels = []model.Tunnel{{ID: "tn", Name: "eu", Kind: model.TunnelWGReverse,
		FromNode: "hub", ToNode: "exit", Enabled: true, Subnet: "10.77.1.0/30",
		ListenPort: 51820, ForwardPolicy: true,
		FromKeyPriv: zeroKey, FromKeyPub: zeroKey, ToKeyPriv: zeroKey, ToKeyPub: zeroKey}}

	files, err := Artifacts(st, "hub")
	if err != nil {
		t.Fatal(err)
	}
	var script string
	for _, f := range files {
		if f.Name == "apply.sh" {
			script = f.Content
		}
	}
	if !strings.Contains(script, `grep -q '^# revhub:'`) {
		t.Error("apply.sh должен опознавать свои конфиги по заголовку, а не удалять всё подряд")
	}
	if !strings.Contains(script, "снят устаревший интерфейс") {
		t.Error("apply.sh не снимает устаревшие интерфейсы")
	}
	// Текущий туннель обязан остаться в keep-списке.
	if !strings.Contains(script, "wg-eu.conf") {
		t.Errorf("в списке сохраняемых нет текущего туннеля:\n%s", script)
	}
	// Снятие должно идти до подъёма, иначе адрес ещё занят.
	if i, j := strings.Index(script, "for stale in"), strings.Index(script, "wg-quick up"); i < 0 || j < 0 || i > j {
		t.Errorf("порядок неверный: снятие (i=%d) должно быть до подъёма (j=%d)", i, j)
	}
}

// Чужая таблица маршрутов не должна перехватываться молча: если в ней уже есть
// default (ручной wg0 с fwmark 100), интерфейс не поднимается, а apply говорит,
// что делать.
func TestWGConfigRefusesForeignDefaultRoute(t *testing.T) {
	var st model.State
	st.Nodes = []model.Node{{ID: "hub", PublicAddr: "194.67.203.189:65423"}, {ID: "exit", PublicAddr: "5.180.31.201:443"}}
	st.Tunnels = []model.Tunnel{{ID: "tn", Name: "eu", Kind: model.TunnelWGReverse,
		FromNode: "hub", ToNode: "exit", Enabled: true, Subnet: "10.77.1.0/30",
		ListenPort: 51820, Mark: 200, ForwardPolicy: true,
		FromKeyPriv: zeroKey, FromKeyPub: zeroKey, ToKeyPriv: zeroKey, ToKeyPub: zeroKey}}

	conf, err := WGConfig(st, st.Tunnels[0], "hub")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(conf, "PreUp = sh -c") || !strings.Contains(conf, "таблица 200") {
		t.Errorf("нет защиты от перехвата чужой таблицы:\n%s", conf)
	}
	// У выхода нет ни метки, ни таблицы — защита ему не нужна.
	exitConf, err := WGConfig(st, st.Tunnels[0], "exit")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(exitConf, "PreUp") {
		t.Errorf("выходу PreUp не нужен:\n%s", exitConf)
	}
}

// Метки не занимают диапазон, который обычно занят ручными настройками.
func TestNextMarkStartsAboveManualRange(t *testing.T) {
	var st model.State
	if got := st.NextMark(); got != 200 {
		t.Fatalf("первая метка = %d, ожидали 200", got)
	}
	st.Tunnels = []model.Tunnel{{Mark: 200}}
	if got := st.NextMark(); got != 201 {
		t.Fatalf("вторая метка = %d, ожидали 201", got)
	}
}

// zeroKey — валидный по форме ключ WireGuard (32 байта в base64).
const zeroKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

// Keepalive по умолчанию не пишем: соединение открывает дозванивающийся узел,
// а PersistentKeepalive — только для случая, когда он за NAT.
func TestWGConfigKeepaliveOnlyWhenRequested(t *testing.T) {
	var st model.State
	st.Nodes = []model.Node{{ID: "hub", PublicAddr: "194.67.203.189:65423"}, {ID: "exit", PublicAddr: "5.180.31.201:443"}}
	st.Tunnels = []model.Tunnel{{ID: "tn", Name: "eu", Kind: model.TunnelWGReverse,
		FromNode: "hub", ToNode: "exit", Enabled: true, Subnet: "10.77.3.0/30",
		ListenPort: 51820, ForwardPolicy: true,
		FromKeyPriv: zeroKey, FromKeyPub: zeroKey, ToKeyPriv: zeroKey, ToKeyPub: zeroKey}}

	conf, err := WGConfig(st, st.Tunnels[0], "exit")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(conf, "PersistentKeepalive") {
		t.Errorf("keepalive не должен появляться без запроса:\n%s", conf)
	}
	if !strings.Contains(conf, "Endpoint = 194.67.203.189:51820") {
		t.Errorf("дозванивающаяся сторона должна знать Endpoint хаба:\n%s", conf)
	}
	// Слушающая сторона не получает ни Endpoint, ни keepalive — иначе хаб
	// пытался бы сам открывать соединение к выходу.
	hubConf, err := WGConfig(st, st.Tunnels[0], "hub")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(hubConf, "Endpoint") || strings.Contains(hubConf, "PersistentKeepalive") {
		t.Errorf("у слушателя не должно быть Endpoint/keepalive:\n%s", hubConf)
	}
	if !strings.Contains(hubConf, "ListenPort = 51820") {
		t.Errorf("слушатель обязан держать ListenPort:\n%s", hubConf)
	}

	st.Tunnels[0].Keepalive = 25
	conf, err = WGConfig(st, st.Tunnels[0], "exit")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(conf, "PersistentKeepalive = 25") {
		t.Errorf("явный keepalive должен попадать в [Peer]:\n%s", conf)
	}
}

// Узел, который выпускает трафик туннеля, обязан получить и wg-quick@ для
// автоподъёма, и постоянный (не только на время работы) ip_forward.
func TestApplyScriptKeepsTunnelAndForwardingAfterReboot(t *testing.T) {
	var st model.State
	st.Nodes = []model.Node{{ID: "hub"}, {ID: "exit"}}
	st.Tunnels = []model.Tunnel{{ID: "tn", Name: "eu", Kind: model.TunnelWGReverse,
		FromNode: "hub", ToNode: "exit", Enabled: true, Subnet: "10.77.3.0/30",
		ListenPort: 51820, ForwardPolicy: true,
		FromKeyPriv: zeroKey, FromKeyPub: zeroKey, ToKeyPriv: zeroKey, ToKeyPub: zeroKey}}

	files, err := Artifacts(st, "exit")
	if err != nil {
		t.Fatal(err)
	}
	var script string
	for _, f := range files {
		if f.Name == "apply.sh" {
			script = f.Content
		}
	}
	for _, want := range []string{
		`systemctl enable "wg-quick@wg-eu.service"`,
		"/etc/sysctl.d/90-revhub.conf",
		"net.ipv4.ip_forward=1",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("в apply.sh нет %q", want)
		}
	}
	// На стороне, которая только отправляет, forwarding не нужен.
	files, err = Artifacts(st, "hub")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f.Name == "apply.sh" && strings.Contains(f.Content, "90-revhub.conf") {
			t.Error("хаб не должен включать ip_forward")
		}
	}
}

// Порты для firewall: клиентские инбаунды и слушатели туннелей, без дублей.
func TestNodePortsCoversInboundsAndListeners(t *testing.T) {
	var st model.State
	st.Nodes = []model.Node{{ID: "hub"}, {ID: "exit"}}
	st.Inbounds = []model.Inbound{
		{ID: "in-1", NodeID: "hub", Tag: "vless", Kind: "vless", Port: 443, Enabled: true},
		{ID: "in-2", NodeID: "hub", Tag: "wg", Kind: model.InboundWireGuard, Port: 51821, Enabled: true},
		{ID: "in-3", NodeID: "hub", Tag: "off", Kind: "vless", Port: 8080, Enabled: false},
		{ID: "in-4", NodeID: "exit", Tag: "other", Kind: "vless", Port: 8443, Enabled: true},
	}
	st.Tunnels = []model.Tunnel{{ID: "tn-1", Name: "eu", Kind: model.TunnelWGReverse,
		FromNode: "hub", ToNode: "exit", Enabled: true, Subnet: "10.77.1.0/30", ListenPort: 51820}}

	got := NodePorts(st, "hub")
	want := []string{"443/tcp", "51821/udp", "51820/udp"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("порты хаба: %v, ожидалось %v", got, want)
	}
	if out := NodePorts(st, "exit"); strings.Join(out, " ") != "8443/tcp" {
		t.Fatalf("порты выходного: %v (слушатель wg-reverse живёт на хабе)", out)
	}
}

// apply.sh открывает порты сам: свежий VPS с ufw иначе «не пускает» клиентов.
func TestApplyScriptOpensPorts(t *testing.T) {
	s := applyScript(nil, false, []string{"443/tcp", "51820/udp"}, false, nil, false)
	for _, want := range []string{"ufw status", `ufw allow "443/tcp"`, `ufw allow "51820/udp"`, "firewall-cmd --permanent --add-port"} {
		if !strings.Contains(s, want) {
			t.Errorf("в apply.sh нет %q", want)
		}
	}
	// без портов — никаких обращений к firewall
	if s := applyScript(nil, false, nil, false, nil, false); strings.Contains(s, "ufw") {
		t.Error("ufw вызывается без портов")
	}
}

func TestApplyRestoresXrayConfigOnFailedRestart(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("apply.sh", applyScript(nil, true, []string{"443/tcp"}, false, nil, false), 0o700)
	write("xray.json", "new", 0o600)
	write("running.json", "old", 0o600)
	write("systemctl", "#!/bin/sh\n[ \"$*\" = 'restart xray' ] && [ \"$(cat \"$XRAY_CONFIG\")\" = old ]\n", 0o700)
	config := filepath.Join(dir, "running.json")
	cmd := exec.Command("bash", filepath.Join(dir, "apply.sh"))
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "XRAY_BIN=true", "XRAY_CONFIG="+config, "STATE_DIR="+dir)
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "Xray не запустился") {
		t.Fatalf("expected apply to report restart failure, got %v: %s", err, out)
	}
	if got, err := os.ReadFile(config); err != nil || string(got) != "old" {
		t.Fatalf("previous Xray config was not restored: %v", err)
	}
}

func TestApplyReportsDNSWriteFailureAfterNetwork(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("apply.sh", applyScript(nil, false, nil, false, nil, true), 0o700)
	write("dnsmasq-revhub.conf", "port=53\n", 0o600)
	write("dns-hosts", "", 0o600)
	write("install", "#!/bin/sh\nfor a in \"$@\"; do [ \"$a\" = /etc/dnsmasq.d/revhub.conf ] && exit 1; done\nexit 0\n", 0o700)
	write("systemctl", "#!/bin/sh\nexit 0\n", 0o700)
	cmd := exec.Command("bash", filepath.Join(dir, "apply.sh"))
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("apply сообщил успех при незаписанном DNS: %s", out)
	}
	if !strings.Contains(string(out), "сеть применяется дальше") {
		t.Fatalf("нет предупреждения о частичном применении: %s", out)
	}
}

func TestWGExitArtifactsDoNotRequireXray(t *testing.T) {
	st := model.Demo()
	st.Tunnels[0].Name = "to-some-long-host-example"
	files, err := Artifacts(st, "exit-eu")
	if err != nil {
		t.Fatal(err)
	}
	var iface, script string
	for _, f := range files {
		if strings.HasSuffix(f.Name, ".conf") {
			iface = strings.TrimSuffix(f.Name, ".conf")
		}
		if f.Name == "apply.sh" {
			script = f.Content
		}
	}
	if iface == "" || len(iface) > 15 {
		t.Fatalf("invalid WG interface name: %q", iface)
	}
	if !strings.Contains(script, "wg-quick up") || strings.Contains(script, "restart xray") {
		t.Fatal("a WG-only exit must only apply WireGuard")
	}
}

// Сертификат Let's Encrypt на голый IP лежит в отдельном каталоге, чтобы не
// перетирать доменный сертификат на том же узле.
func TestTLSPathsForIPCertificate(t *testing.T) {
	sni, cert, key := tlsResolve("acmeip", "", "203.0.113.7", "", "")
	if sni != "203.0.113.7" {
		t.Errorf("SNI = %q", sni)
	}
	if cert != "/etc/revhub/tls/ip/fullchain.pem" || key != "/etc/revhub/tls/ip/key.pem" {
		t.Errorf("пути = %q / %q", cert, key)
	}
}

func TestTLSPathsForDomainCertificate(t *testing.T) {
	sni, cert, key := tlsResolve("acme", "vpn.example.com", "", "", "")
	if sni != "vpn.example.com" || cert != "/etc/revhub/tls/fullchain.pem" {
		t.Errorf("sni=%q cert=%q key=%q", sni, cert, key)
	}
}

// Явные пути сильнее умолчаний источника (нужно установщику и тестам).
func TestTLSPathsExplicitWins(t *testing.T) {
	_, cert, key := tlsResolve("selfsigned", "", "1.2.3.4", "/tmp/a.crt", "/tmp/a.key")
	if cert != "/tmp/a.crt" || key != "/tmp/a.key" {
		t.Errorf("явные пути проигнорированы: %q %q", cert, key)
	}
}
