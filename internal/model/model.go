// Package model описывает состояние панели. Это единственный источник
// правды: конфиги xray и WireGuard — производные от этих структур.
package model

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

const StateVersion = 1

const (
	InboundVLESS     = "vless"
	InboundWireGuard = "wireguard"
)

// Kind'ы туннелей.
const (
	TunnelWG        = "wg"         // слушает дальний (exit), дозванивается ближний (hub)
	TunnelWGReverse = "wg-reverse" // слушает ближний (hub), дозванивается дальний (exit)
	TunnelVLESS     = "vless"      // дальний слушает VLESS, ближний ходит как клиент
)

// Теги служебных исходящих.
const (
	TagDirect = "direct"
	TagBlock  = "block"
	TagTunnel = "tun:" // + имя туннеля
)

type State struct {
	Version  int       `json:"version"`
	Nodes    []Node    `json:"nodes"`
	Inbounds []Inbound `json:"inbounds"`
	Tunnels  []Tunnel  `json:"tunnels"`
	Clients  []Client  `json:"clients"`
	Routes   []Rule    `json:"routes"`
}

type Node struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Role       string `json:"role"` // entry | exit | both
	PublicAddr string `json:"public_addr"`
	Core       string `json:"core"` // имя systemd-юнита ядра, по умолчанию xray

	// Управление по SSH. Секрет живёт в secrets.json, а не здесь.
	SSHAddr    string `json:"ssh_addr"`     // host:port, пусто = порт 22 от PublicAddr
	SSHUser    string `json:"ssh_user"`     // root по умолчанию
	SSHAuth    string `json:"ssh_auth"`     // password | key | none
	SSHKeyFile string `json:"ssh_key_file"` // путь к приватному ключу на машине панели
	HostKey    string `json:"host_key"`     // отпечаток ключа SSH (TOFU: записали при первой установке)

	// Состояние: заполняется панелью, не редактируется руками.
	Status        string `json:"status"` // unknown | alive | dead
	LatencyMS     int    `json:"latency_ms"`
	HandshakeAge  int    `json:"handshake_age"`  // секунды с последнего handshake WG, -1 = нет данных
	LastCheck     string `json:"last_check"`     // RFC3339
	LastBootstrap string `json:"last_bootstrap"` // RFC3339, когда панель последний раз ставила файлы
	MgmtVia       string `json:"mgmt_via"`       // tunnel:<имя> | direct
	BootstrapLog  string `json:"bootstrap_log"`  // хвост лога последней установки
}

type Inbound struct {
	ID         string `json:"id"`
	NodeID     string `json:"node_id"`
	Tag        string `json:"tag"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`   // vless | wireguard
	Listen     string `json:"listen"` // 0.0.0.0 | 127.0.0.1
	Port       int    `json:"port"`
	Transport  string `json:"transport"` // tcp | ws | xhttp
	Security   string `json:"security"`  // reality | tls | none
	SNI        string `json:"sni"`
	Dest       string `json:"dest"` // reality: куда fallback'ить, host:port
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	ShortID    string `json:"short_id"`
	Path       string `json:"path"`
	Flow       string `json:"flow"`
	// TLS. Источник сертификата выбирается явно:
	//   acme       — домен, сертификат выпускает acme.sh на узле
	//   acmeip     — голый IP через Let's Encrypt (shortlived, ~6 дней)
	//   selfsigned — на голый IP (CA такие не выдают), клиенту нужен пин/allowInsecure
	//   file       — готовые файлы
	CertSource string            `json:"cert_source"`
	Domain     string            `json:"domain"` // для acme и для SNI
	IP         string            `json:"ip"`     // для selfsigned: что попадёт в SAN
	CertFile   string            `json:"cert_file"`
	KeyFile    string            `json:"key_file"`
	SelfSigned bool              `json:"self_signed"`
	CertSHA256 string            `json:"cert_sha256,omitempty"` // SHA-256 of a self-signed panel certificate
	Enabled    bool              `json:"enabled"`
	WireGuard  *WireGuardInbound `json:"wireguard,omitempty"`
}

type Tunnel struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	FromNode string `json:"from_node_id"`
	ToNode   string `json:"to_node_id"`
	Enabled  bool   `json:"enabled"`

	// WireGuard
	Subnet        string `json:"subnet"` // 10.77.N.0/30
	ListenPort    int    `json:"listen_port"`
	Keepalive     int    `json:"keepalive"`
	FromKeyPriv   string `json:"from_key_private"`
	FromKeyPub    string `json:"from_key_public"`
	ToKeyPriv     string `json:"to_key_private"`
	ToKeyPub      string `json:"to_key_public"`
	Mark          int    `json:"mark"`
	PublicPort    int    `json:"public_port"`    // внешний порт, если NAT мапит не в ListenPort
	EgressIface   string `json:"egress_iface"`   // на стороне to: куда NAT'ить
	ForwardPolicy bool   `json:"forward_policy"` // to: включить ip_forward и NAT

	// VLESS
	UUID        string `json:"uuid"`
	Transport   string `json:"transport"`
	Security    string `json:"security"`
	SNI         string `json:"sni"`
	Dest        string `json:"dest"`
	Path        string `json:"path"`
	Flow        string `json:"flow"`
	PrivateKey  string `json:"private_key"` // приёмная сторона (reality/tls)
	PublicKey   string `json:"public_key"`
	CertSource  string `json:"cert_source"` // acme | selfsigned | file
	Domain      string `json:"domain"`
	IP          string `json:"ip"`
	CertFile    string `json:"cert_file"` // приёмная сторона при security=tls
	KeyFile     string `json:"key_file"`
	Pin         string `json:"pin"` // base64(sha256 сертификата) для pinnedPeerCertificateChainSha256
	ShortID     string `json:"short_id"`
	ListenPortT int    `json:"listen_port_in"` // порт, на котором слушает дальний конец (vless)
}

type Client struct {
	ID        string                   `json:"id"`
	Email     string                   `json:"email"`
	UUID      string                   `json:"uuid"`
	Enabled   bool                     `json:"enabled"`
	ExpiresAt string                   `json:"expires_at"` // RFC3339, пусто = бессрочно
	QuotaGB   float64                  `json:"quota_gb"`   // 0 = без квоты
	Inbounds  []string                 `json:"inbounds"`   // id инбаундов
	SubToken  string                   `json:"sub_token"`
	Flow      string                   `json:"flow"`
	WireGuard map[string]WireGuardPeer `json:"wireguard,omitempty"` // по ID инбаунда
}

func (c Client) Expired() bool {
	if c.ExpiresAt == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, c.ExpiresAt)
	return err != nil || !time.Now().Before(t)
}

// EffectiveFlow restricts Vision to VLESS over TCP with TLS or REALITY.
func EffectiveFlow(flow, transport, security string) string {
	if flow == "xtls-rprx-vision" && (transport == "" || transport == "tcp") && (security == "tls" || security == "reality") {
		return flow
	}
	return ""
}

func (in Inbound) ClientFlow(c Client) string {
	flow := c.Flow
	if flow == "" {
		flow = in.Flow
	}
	return EffectiveFlow(flow, in.Transport, in.Security)
}

type Rule struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	NodeID   string   `json:"node_id"` // "" = для всех узлов
	Enabled  bool     `json:"enabled"`
	User     []string `json:"user"`
	Inbound  []string `json:"inbound"`
	Domain   []string `json:"domain"`
	IP       []string `json:"ip"`
	Port     string   `json:"port"`
	Network  string   `json:"network"` // tcp | udp | tcp,udp | ""
	Outbound string   `json:"outbound"`
}

// ---------------------------------------------------------------- утилиты

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand недоступен: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// NewID возвращает короткий идентификатор вида "nd-3f9a1c2b".
func NewID(prefix string) string { return prefix + "-" + randHex(4) }

// GenUUID — UUIDv4 в текстовом виде (формат, который ждёт VLESS).
func GenUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// GenWGKeys — пара ключей WireGuard в том виде, в каком их ждёт wg-quick.
func GenWGKeys() (priv, pub string, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()),
		base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// GenRealityKeys — пара X25519 для REALITY: base64url без паддинга,
// как у `xray x25519`.
func GenRealityKeys() (priv, pub string, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(k.Bytes()), enc.EncodeToString(k.PublicKey().Bytes()), nil
}

func GenShortID() string { return randHex(8) }

func GenToken() string { return randHex(16) }

// SubnetAddrs возвращает адреса концов туннеля для подсети /30:
// from = .1, to = .2.
func SubnetAddrs(subnet string) (from, to string, err error) {
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", "", fmt.Errorf("подсеть %q: %w", subnet, err)
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 || ones != 30 {
		return "", "", fmt.Errorf("подсеть %q: нужна IPv4 /30", subnet)
	}
	base := ipnet.IP.To4()
	if base == nil {
		return "", "", fmt.Errorf("подсеть %q: не IPv4", subnet)
	}
	a := make(net.IP, 4)
	b := make(net.IP, 4)
	copy(a, base)
	copy(b, base)
	a[3] += 1
	b[3] += 2
	return a.String(), b.String(), nil
}

// NextSubnet подбирает следующую свободную подсеть 10.77.N.0/30.
func (s State) NextSubnet() string {
	used := map[byte]bool{}
	for _, t := range s.Tunnels {
		if _, ipnet, err := net.ParseCIDR(t.Subnet); err == nil {
			if v4 := ipnet.IP.To4(); v4 != nil {
				used[v4[2]] = true
			}
		}
	}
	for i := 1; i < 255; i++ {
		if !used[byte(i)] {
			return fmt.Sprintf("10.77.%d.0/30", i)
		}
	}
	return "10.77.254.0/30"
}

// NextMark подбирает свободную метку (по всем туннелям, чтобы не думать о
// коллизиях между узлами).
func (s State) NextMark() int {
	used := map[int]bool{}
	for _, t := range s.Tunnels {
		used[t.Mark] = true
	}
	for i := 0x64; i < 0x1000; i++ {
		if !used[i] {
			return i
		}
	}
	return 0x64
}

func (t Tunnel) Tag() string { return TagTunnel + t.Name }

// WGInterface preserves valid legacy interface names and shortens long ones.
func (t Tunnel) WGInterface() string {
	name := "wg-" + t.Name
	if len(name) <= 15 && strings.IndexFunc(name, func(c rune) bool {
		return !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_=+.-", c))
	}) == -1 {
		return name
	}
	sum := sha256.Sum256([]byte(t.ID + "/" + t.Name))
	return fmt.Sprintf("wg-%x", sum[:6])
}

// ListenerNode — узел, который держит ListenPort; DialerNode — тот, кто
// дозванивается. Направление трафика всегда From → To.
func (t Tunnel) ListenerNode() string {
	if t.Kind == TunnelWGReverse {
		return t.FromNode
	}
	return t.ToNode
}

func (t Tunnel) DialerNode() string {
	if t.Kind == TunnelWGReverse {
		return t.ToNode
	}
	return t.FromNode
}

func (t Tunnel) Touches(nodeID string) bool {
	return t.FromNode == nodeID || t.ToNode == nodeID
}

// Normalize дополняет пустые поля разумными значениями. Вызывается при
// сохранении состояния и при создании сущностей из UI.
func (s *State) Normalize() {
	if s.Version == 0 {
		s.Version = StateVersion
	}
	for i := range s.Nodes {
		n := &s.Nodes[i]
		if n.Core == "" {
			n.Core = "xray"
		}
		if n.Role == "" {
			n.Role = "both"
		}
		if n.SSHUser == "" {
			n.SSHUser = "root"
		}
		if n.SSHAuth == "" {
			n.SSHAuth = "key"
		}
		if n.Status == "" {
			n.Status = "unknown"
		}
		if n.SSHAddr == "" && n.PublicAddr != "" {
			host := n.PublicAddr
			if i := strings.LastIndex(host, ":"); i > 0 {
				host = host[:i]
			}
			n.SSHAddr = host + ":22"
		}
	}
	for i := range s.Inbounds {
		in := &s.Inbounds[i]
		if in.Kind == "" {
			in.Kind = InboundVLESS
		}
		if in.Kind == InboundWireGuard {
			in.normalizeWireGuard()
			continue
		}
		if in.Transport == "" {
			in.Transport = "tcp"
		}
		if in.Security == "" {
			in.Security = "tls" // по умолчанию обычный TLS, reality — осознанный выбор
		}
		if in.Listen == "" {
			in.Listen = "0.0.0.0"
		}
		if in.Flow == "" && in.Security == "reality" && in.Transport == "tcp" {
			in.Flow = "xtls-rprx-vision"
		}
		if in.Security == "tls" && in.CertSource == "" {
			switch {
			case in.CertFile != "" && in.KeyFile != "":
				in.CertSource = "file"
			case in.Domain != "":
				in.CertSource = "acme"
			case in.IP != "":
				in.CertSource = "selfsigned"
			}
		}
	}
	for i := range s.Tunnels {
		t := &s.Tunnels[i]
		if t.Subnet == "" {
			t.Subnet = s.NextSubnet()
		}
		if t.Mark == 0 {
			t.Mark = s.NextMark()
		}
		// Keepalive намеренно не подставляем: 0 = «не использовать».
		// PersistentKeepalive нужен только если дозванивающаяся сторона за NAT,
		// иначе это лишний фоновый трафик от выхода к хабу.
		if t.ListenPort == 0 {
			t.ListenPort = 51820
		}

		if t.Kind == TunnelVLESS {
			if t.Transport == "" {
				t.Transport = "tcp"
			}
			if t.Security == "" {
				t.Security = "reality"
			}
			if t.ListenPortT == 0 {
				t.ListenPortT = 443
			}
			if t.Flow == "" && t.Security == "reality" && t.Transport == "tcp" {
				t.Flow = "xtls-rprx-vision"
			}
			if t.Security == "reality" && (t.PrivateKey == "" || t.PublicKey == "") {
				priv, pub, err := GenRealityKeys()
				if err == nil {
					t.PrivateKey, t.PublicKey = priv, pub
				}
			}
			if t.ShortID == "" {
				t.ShortID = GenShortID()
			}
			if t.UUID == "" {
				t.UUID = GenUUID()
			}
		}
	}
	for i := range s.Clients {
		c := &s.Clients[i]
		if c.ID == "" {
			c.ID = NewID("cl")
		}
		if c.UUID == "" {
			c.UUID = GenUUID()
		}
		if c.SubToken == "" {
			c.SubToken = GenToken()
		}
	}
	s.normalizeWireGuardPeers()
}

// ValidTags возвращает теги исходящих, существующие на узле. Тег туннеля
// существует только на стороне From: на стороне To трафик приходит ядерным
// интерфейсом, и объекта в xray там нет.
func (s State) ValidTags(nodeID string) map[string]bool {
	m := map[string]bool{TagDirect: true, TagBlock: true}
	for _, t := range s.Tunnels {
		if t.Enabled && t.FromNode == nodeID {
			m[t.Tag()] = true
		}
	}
	return m
}

// HasInboundTag учитывает обычные инбаунды и принимающую сторону VLESS-туннеля.
func (s State) HasInboundTag(nodeID, tag string) bool {
	for _, in := range s.Inbounds {
		if in.NodeID == nodeID && in.Tag == tag {
			return true
		}
	}
	for _, tunnel := range s.Tunnels {
		if tunnel.Kind == TunnelVLESS && tunnel.ToNode == nodeID && tunnel.Tag() == tag {
			return true
		}
	}
	return false
}

// Validate проверяет инварианты из docs/DATA-MODEL.md.
func (s State) Validate() error {
	var errs []string
	add := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }

	nodes := map[string]bool{}
	ids := map[string]string{}
	claim := func(id, what string) {
		if id == "" {
			add("%s: пустой id", what)
			return
		}
		if prev, ok := ids[id]; ok {
			add("id %q дублируется: %s и %s", id, prev, what)
		}
		ids[id] = what
	}

	for _, n := range s.Nodes {
		claim(n.ID, "узел "+n.Name)
		nodes[n.ID] = true
		switch n.Role {
		case "entry", "exit", "both":
		default:
			add("узел %s: неизвестная роль %q", n.ID, n.Role)
		}
	}
	if len(s.Nodes) == 0 {
		add("нет ни одного узла")
	}

	tags := map[string]bool{}
	for i, in := range s.Inbounds {
		claim(in.ID, "инбаунд "+in.Tag)
		if !nodes[in.NodeID] {
			add("инбаунд %s: узел %q не найден", in.Tag, in.NodeID)
		}
		if in.Tag == "" {
			add("инбаунд %s: пустой tag", in.ID)
		}
		if tags[in.NodeID+"/"+in.Tag] {
			add("узел %s: тег инбаунда %q не уникален", in.NodeID, in.Tag)
		}
		tags[in.NodeID+"/"+in.Tag] = true
		if in.Port <= 0 || in.Port > 65535 {
			add("инбаунд %s: некорректный порт %d", in.Tag, in.Port)
		}
		switch in.Kind {
		case InboundWireGuard:
			s.validateWireGuard(in, add)
			s.validateWireGuardPort(i, add)
			continue
		case InboundVLESS, "":
		default:
			add("инбаунд %s: неизвестный протокол %q", in.Tag, in.Kind)
			continue
		}
		if in.Security == "reality" {
			if in.PrivateKey == "" || in.ShortID == "" || in.Dest == "" || in.SNI == "" {
				add("инбаунд %s: для reality нужны private_key, short_id, dest, sni", in.Tag)
			}
		}
		source := in.CertSource
		if source == "panel" {
			source = "file" // API resolves the configured local certificate and key paths.
		}
		if err := validateTLS("инбаунд "+in.Tag, in.Security, source, in.Domain, in.IP, in.CertFile, in.KeyFile); err != nil {
			add("%v", err)
		}
		if in.Transport == "ws" || in.Transport == "xhttp" {
			if in.Path == "" {
				add("инбаунд %s: для %s нужен path", in.Tag, in.Transport)
			}
		}
	}

	names := map[string]bool{}
	marks := map[string]int{}
	for _, t := range s.Tunnels {
		claim(t.ID, "туннель "+t.Name)
		if names[t.Name] {
			add("туннель %q: имя не уникально (оно же тег исходящего)", t.Name)
		}
		names[t.Name] = true
		if !nodes[t.FromNode] {
			add("туннель %s: узел from %q не найден", t.Name, t.FromNode)
		}
		if !nodes[t.ToNode] {
			add("туннель %s: узел to %q не найден", t.Name, t.ToNode)
		}
		if t.FromNode == t.ToNode {
			add("туннель %s: from и to совпадают", t.Name)
		}
		switch t.Kind {
		case TunnelWG, TunnelWGReverse:
			if t.FromKeyPriv == "" || t.ToKeyPriv == "" {
				add("туннель %s: нет ключей WG", t.Name)
			}
			if _, _, err := SubnetAddrs(t.Subnet); err != nil {
				add("туннель %s: %v", t.Name, err)
			}
			if t.Mark == 0 {
				add("туннель %s: mark не задан", t.Name)
			}
			for _, n := range []string{t.FromNode, t.ToNode} {
				if prev, ok := marks[n]; ok && prev != 0 && prev == t.Mark {
					add("узел %s: метка %d занята двумя туннелями", n, t.Mark)
				}
				marks[n] = t.Mark
			}
		case TunnelVLESS:
			if t.UUID == "" {
				add("туннель %s: нет UUID", t.Name)
			}
			if t.Security == "reality" && (t.PublicKey == "" || t.ShortID == "" || t.SNI == "") {
				add("туннель %s: для reality нужны public_key, short_id, sni", t.Name)
			}
			if err := validateTLS("туннель "+t.Name, t.Security, t.CertSource, t.Domain, t.IP, t.CertFile, t.KeyFile); err != nil {
				add("%v", err)
			}
		default:
			add("туннель %s: неизвестный kind %q", t.Name, t.Kind)
		}
	}

	inb := map[string]Inbound{}
	for _, in := range s.Inbounds {
		inb[in.ID] = in
	}
	for _, c := range s.Clients {
		claim(c.ID, "клиент "+c.Email)
		if c.Email == "" {
			add("клиент %s: пустой email (он же метка в правилах)", c.ID)
		}
		if _, err := parseUUID(c.UUID); err != nil {
			add("клиент %s: %v", c.Email, err)
		}
		if c.SubToken == "" {
			add("клиент %s: нет sub_token", c.Email)
		}
		if len(c.Inbounds) == 0 {
			add("клиент %s: не привязан ни к одному инбаунду", c.Email)
		}
		for _, id := range c.Inbounds {
			if _, ok := inb[id]; !ok {
				add("клиент %s: инбаунд %q не найден", c.Email, id)
			}
		}
	}

	for i, r := range s.Routes {
		claim(r.ID, "правило "+r.Name)
		if r.Outbound == "" {
			add("правило #%d %s: не указан исходящий", i+1, r.Name)
			continue
		}
		if r.NodeID == "" {
			found := false
			for n := range nodes {
				if s.ValidTags(n)[r.Outbound] {
					found = true
					break
				}
			}
			if !found {
				add("правило #%d %s: исходящего %q нет ни на одном узле", i+1, r.Name, r.Outbound)
			}
		} else if !s.ValidTags(r.NodeID)[r.Outbound] {
			add("правило #%d %s: на узле %s нет исходящего %q", i+1, r.Name, r.NodeID, r.Outbound)
		}
		if r.Enabled {
			for _, tag := range r.Inbound {
				found := false
				for nodeID := range nodes {
					if (r.NodeID == "" || r.NodeID == nodeID) && s.ValidTags(nodeID)[r.Outbound] && s.HasInboundTag(nodeID, tag) {
						found = true
						break
					}
				}
				if !found {
					add("правило #%d %s: инбаунд %q и исходящий %q должны быть на одном узле", i+1, r.Name, tag, r.Outbound)
				}
			}
		}
		for _, u := range r.User {
			found := false
			for _, c := range s.Clients {
				if c.Email == u {
					found = true
					break
				}
			}
			if !found {
				add("правило #%d %s: пользователь %q не найден", i+1, r.Name, u)
			}
		}
		if r.Network != "" && r.Network != "tcp" && r.Network != "udp" && r.Network != "tcp,udp" {
			add("правило #%d %s: network должен быть tcp, udp или tcp,udp", i+1, r.Name)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "\n"))
	}
	return nil
}

// validateTLS проверяет, что для security=tls выбран внятный источник
// сертификата: acme требует домен, selfsigned — IP или домен, file — файлы.
func validateTLS(what, security, source, domain, ip, certFile, keyFile string) error {
	if security != "tls" {
		return nil
	}
	switch source {
	case "acme":
		if domain == "" {
			return fmt.Errorf("%s: для выпуска по домену нужно поле domain", what)
		}
	case "acmeip":
		if ip == "" {
			return fmt.Errorf("%s: для сертификата Let's Encrypt на IP нужно поле ip", what)
		}
	case "selfsigned":
		if ip == "" && domain == "" {
			return fmt.Errorf("%s: для самоподписанного нужен ip (или domain)", what)
		}
	case "file":
		if certFile == "" || keyFile == "" {
			return fmt.Errorf("%s: для своего сертификата нужны cert_file и key_file", what)
		}
	default:
		return fmt.Errorf("%s: для security=tls укажи cert_source: acme, selfsigned или file", what)
	}
	return nil
}

func parseUUID(s string) (string, error) {
	parts := strings.Split(s, "-")
	if len(parts) != 5 || len(parts[0]) != 8 || len(parts[1]) != 4 || len(parts[2]) != 4 ||
		len(parts[3]) != 4 || len(parts[4]) != 12 {
		return "", fmt.Errorf("UUID %q не в формате 8-4-4-4-12", s)
	}
	if _, err := hex.DecodeString(strings.Join(parts, "")); err != nil {
		return "", fmt.Errorf("UUID %q не hex", s)
	}
	return s, nil
}
