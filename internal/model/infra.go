package model

import (
	"net"
	"net/netip"
	"strings"
)

// Внутренняя инфраструктура — третий сетевой уровень: отдельный системный
// WireGuard-интерфейс для серверов и машин инфры. Своя подсеть, свои пиры,
// общий интернет-шлюз через существующие выходные туннели.
//
// Отличия от клиентского WG (inbound kind=wireguard): пиры — не пользователи,
// а узлы инфраструктуры; сеть L3 с ICMP и полным взаимодействием пиров; пиры
// добавляются без перезапуска интерфейса и без обновления пользовательских
// подписок.

const (
	DefaultInfraSubnet    = "10.89.0.0/24"
	DefaultInfraPort      = 51840
	DefaultInfraInterface = "wg-infra"
)

// InfraConfig — конфигурация инфраструктурной сети на узле-хабе.
type InfraConfig struct {
	Enabled    bool   `json:"enabled"`
	NodeID     string `json:"node_id"`     // узел, где поднят интерфейс (обычно хаб)
	Interface  string `json:"interface"`   // имя WG-интерфейса (wg-infra)
	Subnet     string `json:"subnet"`      // 10.89.0.0/24 по умолчанию
	ListenPort int    `json:"listen_port"` // UDP-порт
	PrivateKey string `json:"private_key"` // ключ сервера (генерирует панель)
	PublicKey  string `json:"public_key"`

	// Egress — куда инфра-пиры выходят в интернет: пусто/direct — NAT хаба,
	// tun:<имя> — через существующий обратный туннель. Тот же механизм,
	// что у клиентских инбаундов: ip rule + таблица + masquerade.
	Egress string `json:"egress,omitempty"`
}

// ServerAddress — адрес хаба в инфра-подсети (.1).
func (ic InfraConfig) ServerAddress() string {
	p, err := netip.ParsePrefix(ic.Subnet)
	if err != nil {
		return ""
	}
	return p.Addr().Next().String()
}

// InfraPeer — машина инфраструктуры: ключи, адрес, имя.
type InfraPeer struct {
	ID           string `json:"id"`
	Name         string `json:"name"`               // человекочитаемое (srv-db, laptop-vadim)
	Hostname     string `json:"hostname,omitempty"` // для будущего DNS
	Address      string `json:"address"`            // 10.89.0.N/32, выдаёт Normalize
	PrivateKey   string `json:"private_key"`
	PublicKey    string `json:"public_key"`
	PresharedKey string `json:"preshared_key"`
	Enabled      bool   `json:"enabled"`

	// Egress — личный выход пира: пусто = как у инфра-сети, direct = NAT хаба,
	// tun:<имя> = конкретный туннель. Тот же смысл, что у клиентов.
	Egress string `json:"egress,omitempty"`
}

func (p InfraPeer) display() string {
	if p.Name != "" {
		return p.Name
	}
	return p.ID
}

// normalizeInfra дополняет инфра-конфиг и пиров дефолтами. Вызывается из
// State.Normalize; порядок — после клиентских WG-сетей, чтобы подсети не
// пересекались уже на этапе валидации.
func (s *State) normalizeInfra() {
	if s.Infra == nil || !s.Infra.Enabled {
		return
	}
	ic := s.Infra
	if ic.Interface == "" {
		ic.Interface = DefaultInfraInterface
	}
	// Имя интерфейса фиксировано: apply.sh узнаёт инфра-конфиг по файлу
	// wg-infra.conf и синхронизирует пиров через wg syncconf без перезапуска.
	ic.Interface = DefaultInfraInterface
	if ic.Subnet == "" {
		ic.Subnet = DefaultInfraSubnet
	}
	if ic.ListenPort == 0 {
		ic.ListenPort = DefaultInfraPort
	}
	if ic.PrivateKey == "" || ic.PublicKey == "" {
		fillWGKeys(&ic.PrivateKey, &ic.PublicKey)
	}

	// Автовыдача адресов пирам: первый свободный со .2 (адрес хаба — .1).
	p, err := netip.ParsePrefix(ic.Subnet)
	if err != nil {
		return
	}
	taken := map[byte]bool{1: true} // .1 — сервер
	for _, p2 := range s.InfraPeers {
		if a, err := netip.ParsePrefix(p2.Address); err == nil && p.Contains(a.Addr()) {
			taken[a.Addr().As4()[3]] = true
		}
	}
	for i := range s.InfraPeers {
		pr := &s.InfraPeers[i]
		if pr.ID == "" {
			pr.ID = NewID("infra")
		}
		if pr.PrivateKey == "" || pr.PublicKey == "" {
			fillWGKeys(&pr.PrivateKey, &pr.PublicKey)
		}
		if pr.PresharedKey == "" {
			key, _, _ := GenWGKeys() // PSK — отдельный случайный 32-байтный ключ
			pr.PresharedKey = key
		}
		if pr.Hostname == "" && pr.Name != "" {
			pr.Hostname = NormalizeName(pr.Name)
		}
		if pr.Address != "" {
			continue
		}
		for n := 2; n < 255; n++ {
			if taken[byte(n)] {
				continue
			}
			ip := net.IP(p.Addr().AsSlice()).To4()
			ip[3] = byte(n)
			pr.Address = ip.String() + "/32"
			taken[byte(n)] = true
			break
		}
	}
}

// validateInfra — инварианты инфра-сети: отдельная подсеть, уникальные
// адреса/ключи, валидный egress.
func (s State) validateInfra(add func(string, ...any)) {
	ic := s.Infra
	if ic == nil || !ic.Enabled {
		return
	}
	if !nodesHasID(s, ic.NodeID) && ic.NodeID != "" {
		add("инфра: узел %q не найден", ic.NodeID)
	}
	if ic.Interface == "" {
		add("инфра: нет имени интерфейса")
	}
	p, err := netip.ParsePrefix(ic.Subnet)
	if err != nil || !p.Addr().Is4() {
		add("инфра: некорректная подсеть %q", ic.Subnet)
		return
	}
	if p.Bits() < 8 || p.Bits() > 30 {
		add("инфра: подсеть %q — нужна IPv4 от /8 до /30", ic.Subnet)
	}
	// Инфра-подсеть не должна пересекаться с клиентскими WG-сетями и общей
	// сетью туннелей: иначе маршрутизация становится неоднозначной.
	for _, in := range s.Inbounds {
		if in.Kind == InboundWireGuard && in.WireGuard != nil {
			if q, ok := wireGuardSubnet(in.WireGuard.Subnet); ok && p.Overlaps(q) {
				add("инфра: подсеть %s пересекается с клиентской сетью инбаунда %s (%s)", ic.Subnet, in.Tag, in.WireGuard.Subnet)
			}
		}
	}
	if ic.ListenPort <= 0 || ic.ListenPort > 65535 {
		add("инфра: некорректный порт %d", ic.ListenPort)
	}
	if pub := wgPublicKey(ic.PrivateKey); pub == "" || pub != ic.PublicKey {
		add("инфра: неверная пара ключей сервера")
	}
	// egress — как у инбаундов: direct или туннель, начинающийся на этом узле
	if ic.Egress != "" && ic.Egress != TagDirect {
		name, ok := strings.CutPrefix(ic.Egress, TagTunnel)
		found := false
		for _, t := range s.Tunnels {
			if t.Enabled && t.Name == name && t.FromNode == ic.NodeID {
				found = true
			}
		}
		if !ok || name == "" || !found {
			add("инфра: выход %q — нет включённого туннеля %s на узле %s", ic.Egress, name, ic.NodeID)
		}
	}

	addresses := map[string]string{}
	keys := map[string]bool{ic.PublicKey: true}
	for _, pr := range s.InfraPeers {
		who := "инфра-пир " + pr.display()
		if pr.Name == "" {
			add("%s: пустое имя", who)
		}
		if !pr.Enabled {
			continue
		}
		addr, err := netip.ParsePrefix(pr.Address)
		if err != nil || addr.Bits() != 32 || !p.Contains(addr.Addr()) {
			add("%s: неверный адрес %q", who, pr.Address)
			continue
		}
		ip := addr.Addr().String()
		if prev := addresses[ip]; prev != "" {
			add("%s: адрес %s уже занят пиром %s", who, ip, prev)
		}
		addresses[ip] = pr.display()
		if ip == ic.ServerAddress() {
			add("%s: адрес %s совпадает с адресом сервера", who, ip)
		}
		if pub := wgPublicKey(pr.PrivateKey); pub == "" || pub != pr.PublicKey || keys[pub] {
			add("%s: неверная или повторяющаяся пара ключей", who)
		}
		keys[pr.PublicKey] = true
		if pr.Egress != "" && pr.Egress != TagDirect {
			name, ok := strings.CutPrefix(pr.Egress, TagTunnel)
			found := false
			for _, t := range s.Tunnels {
				if t.Enabled && t.Name == name && t.FromNode == ic.NodeID {
					found = true
				}
			}
			if !ok || name == "" || !found {
				add("%s: выход %q — нет включённого туннеля %s на узле %s", who, pr.Egress, name, ic.NodeID)
			}
		}
	}
}

func nodesHasID(s State, id string) bool {
	for _, n := range s.Nodes {
		if n.ID == id {
			return true
		}
	}
	return false
}
