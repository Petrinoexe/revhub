package gen

import (
	"encoding/json"
	"strings"
	"testing"

	"revhub/internal/model"
)

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
		"Address = 10.77.1.1/30",
		"PostUp = ip -4 route replace 10.77.1.2/32 dev %i", // маршрут для SSH через туннель
		"PostUp = ip rule add fwmark 100 lookup 100",
		"ip -4 route replace default dev %i table 100",
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
		"Address = 10.77.1.2/30",
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
