package model

import (
	"strings"
	"testing"
)

func infraState() State {
	st := Demo()
	st.Infra = &InfraConfig{Enabled: true, NodeID: "hub"}
	return st
}

func TestInfraNormalizeDefaults(t *testing.T) {
	st := infraState()
	st.InfraPeers = []InfraPeer{{Name: "srv-db"}, {Name: "srv-app"}}
	st.Normalize()

	ic := st.Infra
	if ic.Interface != "wg-infra" || ic.Subnet != "10.89.0.0/24" || ic.ListenPort != 51840 {
		t.Fatalf("дефолты инфры: %+v", ic)
	}
	if ic.PrivateKey == "" || ic.PublicKey == "" {
		t.Error("ключи сервера не сгенерированы")
	}
	if got := ic.ServerAddress(); got != "10.89.0.1" {
		t.Errorf("адрес сервера = %q", got)
	}
	for i, p := range st.InfraPeers {
		if p.ID == "" || p.PrivateKey == "" || p.PublicKey == "" || p.PresharedKey == "" {
			t.Errorf("пир %d недозаполнен: %+v", i, p)
		}
		if p.Address == "" {
			t.Errorf("пир %d без адреса", i)
		}
	}
	if st.InfraPeers[0].Address != "10.89.0.2/32" || st.InfraPeers[1].Address != "10.89.0.3/32" {
		t.Errorf("адреса пиров: %s, %s", st.InfraPeers[0].Address, st.InfraPeers[1].Address)
	}
	if st.InfraPeers[0].Hostname != "srv-db" {
		t.Errorf("hostname не выведен из имени: %q", st.InfraPeers[0].Hostname)
	}
	if err := st.Validate(); err != nil {
		t.Fatalf("инфра-состояние невалидно: %v", err)
	}
}

func TestInfraAddressAllocationSkipsTaken(t *testing.T) {
	st := infraState()
	st.InfraPeers = []InfraPeer{
		{Name: "first", Address: "10.89.0.2/32", Enabled: true},
		{Name: "second"}, // должен получить .3
		{Name: "third"},  // .4
	}
	st.Normalize()
	if st.InfraPeers[1].Address != "10.89.0.3/32" || st.InfraPeers[2].Address != "10.89.0.4/32" {
		t.Errorf("адреса: %s, %s", st.InfraPeers[1].Address, st.InfraPeers[2].Address)
	}
}

func TestInfraValidateRejectsOverlapWithClientSubnet(t *testing.T) {
	st := infraState()
	st.Inbounds = append(st.Inbounds, Inbound{
		ID: "in-wg", NodeID: "hub", Tag: "wg", Kind: InboundWireGuard, Enabled: true,
	})
	st.Normalize() // клиентская сеть получит 10.88.0.0/24
	st.Infra.Subnet = "10.88.0.0/24"
	if err := st.Validate(); err == nil || !strings.Contains(err.Error(), "пересекается") {
		t.Fatalf("пересечение подсетей принято: %v", err)
	}
}

func TestInfraValidateRejectsDuplicatePeerAddress(t *testing.T) {
	st := infraState()
	st.InfraPeers = []InfraPeer{
		{Name: "a", Address: "10.89.0.5/32", Enabled: true},
		{Name: "b", Address: "10.89.0.5/32", Enabled: true},
	}
	st.Normalize()
	if err := st.Validate(); err == nil || !strings.Contains(err.Error(), "уже занят") {
		t.Fatalf("дубль адреса принят: %v", err)
	}
}

func TestInfraValidateRejectsServerAddress(t *testing.T) {
	st := infraState()
	st.InfraPeers = []InfraPeer{{Name: "a", Address: "10.89.0.1/32", Enabled: true}}
	st.Normalize()
	if err := st.Validate(); err == nil || !strings.Contains(err.Error(), "сервера") {
		t.Fatalf("адрес сервера принят пиром: %v", err)
	}
}

func TestInfraValidateEgress(t *testing.T) {
	st := infraState()
	st.Normalize()
	st.Infra.Egress = "tun:eu"
	if err := st.Validate(); err != nil {
		t.Fatalf("выход через существующий туннель должен быть валиден: %v", err)
	}
	st.Infra.Egress = "tun:nope"
	if err := st.Validate(); err == nil || !strings.Contains(err.Error(), "нет включённого туннеля") {
		t.Fatalf("несуществующий выход принят: %v", err)
	}
	st.InfraPeers = []InfraPeer{{Name: "a", Enabled: true, Egress: "tun:nope"}}
	st.Infra.Egress = ""
	st.Normalize()
	if err := st.Validate(); err == nil || !strings.Contains(err.Error(), "нет включённого туннеля") {
		t.Fatalf("личный выход пира на несуществующий туннель принят: %v", err)
	}
}

func TestInfraDisabledSkipsValidation(t *testing.T) {
	st := infraState()
	st.Infra.Enabled = false
	st.Infra.Subnet = "мусор"
	if err := st.Validate(); err != nil {
		t.Fatalf("выключенная инфра не должна валидироваться: %v", err)
	}
}

func TestInfraPeerKeysUniqueFromServer(t *testing.T) {
	st := infraState()
	st.InfraPeers = []InfraPeer{{Name: "a", Enabled: true}}
	st.Normalize()
	// Подсовываем пиру ключ сервера
	st.InfraPeers[0].PrivateKey = st.Infra.PrivateKey
	st.InfraPeers[0].PublicKey = st.Infra.PublicKey
	if err := st.Validate(); err == nil || !strings.Contains(err.Error(), "ключ") {
		t.Fatalf("повтор ключа сервера принят: %v", err)
	}
}
