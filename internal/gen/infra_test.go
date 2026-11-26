package gen

import (
	"strings"
	"testing"

	"revhub/internal/model"
)

func infraGenState() model.State {
	st := model.Demo()
	st.Infra = &model.InfraConfig{
		Enabled: true, NodeID: "hub",
		Egress: "tun:eu", // выход через существующий обратный туннель
	}
	st.InfraPeers = []model.InfraPeer{
		{Name: "srv-db", Enabled: true},
		{Name: "srv-app", Enabled: true},
	}
	st.Normalize()
	return st
}

func TestInfraArtifactsRendered(t *testing.T) {
	st := infraGenState()
	files, err := Artifacts(st, "hub")
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]string{}
	for _, f := range files {
		byName[f.Name] = f.Content
	}
	conf, ok := byName["wg-infra.conf"]
	if !ok {
		names := make([]string, 0, len(files))
		for _, f := range files {
			names = append(names, f.Name)
		}
		t.Fatalf("нет wg-infra.conf: %v", names)
	}
	for _, want := range []string{
		"Address = 10.89.0.1/24",
		"ListenPort = 51840",
		"AllowedIPs = 10.89.0.2/32",
		"AllowedIPs = 10.89.0.3/32",
		"PresharedKey =",
		"iif %i lookup",                       // выход через туннель — правило на интерфейс
		"masquerade",                          // NAT на выходной туннель
		"iptables -I FORWARD -i %i -j ACCEPT", // пиры друг друга
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("в wg-infra.conf нет %q\n%s", want, conf)
		}
	}
	apply := byName["apply.sh"]
	if !strings.Contains(apply, "wg syncconf wg-infra") {
		t.Error("apply.sh не синхронизирует пиров без перезапуска")
	}
	if !strings.Contains(apply, "wg-quick up wg-infra") {
		t.Error("apply.sh не поднимает интерфейс с нуля")
	}
	// пиры не должны подниматься общим циклом wg-quick up (это разрыв сессий)
	if strings.Contains(apply, `wg-quick up "wg-infra"`) {
		t.Error("wg-infra попал в общий перезапуск туннелей")
	}
	for _, want := range []string{"51840/udp"} {
		if !strings.Contains(strings.Join(NodePorts(st, "hub"), ","), want) {
			t.Errorf("порт инфры %s не открыт", want)
		}
	}
}

func TestInfraPeerConfig(t *testing.T) {
	st := infraGenState()
	st.InfraPeers[0].DNS = "10.89.0.1, 1.1.1.1"
	conf, ok, err := InfraPeerConfig(st, st.InfraPeers[0])
	if err != nil || !ok {
		t.Fatalf("конфиг пира не отрендерился: %v", err)
	}
	for _, want := range []string{
		"PrivateKey = " + st.InfraPeers[0].PrivateKey,
		"Address = 10.89.0.2/32",
		"DNS = 10.89.0.1, 1.1.1.1",
		"PublicKey = " + st.Infra.PublicKey,
		"PresharedKey = " + st.InfraPeers[0].PresharedKey,
		"AllowedIPs = 0.0.0.0/0",
		"Endpoint = hub.example.com:51840",
		"PersistentKeepalive = 25",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("в клиентском конфиге нет %q\n%s", want, conf)
		}
	}
}

func TestInfraNotRenderedOnOtherNode(t *testing.T) {
	st := infraGenState()
	files, err := Artifacts(st, "exit-eu")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f.Name == "wg-infra.conf" {
			t.Fatal("инфра-интерфейс не должен рендериться на чужом узле")
		}
	}
}

func TestInfraDirectEgressNAT(t *testing.T) {
	st := infraGenState()
	st.Infra.Egress = ""
	conf, ok, err := InfraWGConf(st, "hub")
	if err != nil || !ok {
		t.Fatal(err)
	}
	if !strings.Contains(conf, `iifname "%i" oifname != "%i" masquerade`) {
		t.Errorf("нет NAT напрямую:\n%s", conf)
	}
}

func TestInfraPeerEgressOverrides(t *testing.T) {
	st := infraGenState()
	st.InfraPeers[0].Egress = model.TagDirect
	conf, _, err := InfraWGConf(st, "hub")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(conf, "ip rule add from 10.89.0.2/32 lookup main pref 31900") {
		t.Errorf("личный выход пира напрямую не применён:\n%s", conf)
	}
}

func TestInfraAllowsVPNClientsIntoInfraSubnet(t *testing.T) {
	st := infraGenState()
	st.Inbounds = append(st.Inbounds, model.Inbound{
		ID: "in-wg", NodeID: "hub", Tag: "clients", Kind: model.InboundWireGuard,
		Listen: "0.0.0.0", Port: 51820, Enabled: true,
	})
	st.Normalize()
	conf, ok, err := InfraWGConf(st, "hub")
	if err != nil || !ok {
		t.Fatal(err)
	}
	for _, want := range []string{
		"iptables -I FORWARD -s 10.88.0.0/24 -o %i -j ACCEPT",
		"iptables -I FORWARD -d 10.88.0.0/24 -i %i -j ACCEPT",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("клиенты WG не допущены в инфру: нет %q\n%s", want, conf)
		}
	}
}

func TestInfraDisabledNoArtifacts(t *testing.T) {
	st := model.Demo()
	st.Infra = &model.InfraConfig{Enabled: false}
	files, err := Artifacts(st, "hub")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f.Name == "wg-infra.conf" {
			t.Fatal("выключенная инфра не должна рендериться")
		}
	}
}
