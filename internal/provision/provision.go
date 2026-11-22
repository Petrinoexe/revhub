// Package provision — «добавить хост и всё поставить»: узел, туннель, секрет,
// артефакты для обеих сторон, установка по SSH и проверка результата.
package provision

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"revhub/internal/bootstrap"
	"revhub/internal/certs"
	"revhub/internal/gen"
	"revhub/internal/model"
	"revhub/internal/secrets"
	"revhub/internal/sshx"
	"revhub/internal/store"
)

type Service struct {
	Store   *store.Store
	Secrets *secrets.Store
	OutDir  string
	Open    bootstrap.Open // по умолчанию SSH; подменяется тестами
}

type Request struct {
	NodeID       string `json:"node_id"` // если задан — только переустановка, без создания
	Name         string `json:"name"`
	Addr         string `json:"addr"` // IP или домен выходного
	Port         int    `json:"port"` // порт VLESS-инбаунда на выходном
	HubNodeID    string `json:"hub_node_id"`
	TunnelKind   string `json:"tunnel_kind"` // wg | wg-reverse | vless
	TLSBy        string `json:"tls_by"`      // domain | ip — на чём TLS у выходного
	Domain       string `json:"domain"`      // поле для варианта «по домену»
	IP           string `json:"ip"`          // поле для варианта «по IP»
	ACMEEmail    string `json:"acme_email"`
	ACMEDNS      string `json:"acme_dns"`       // пусто = HTTP-01
	ACMEHTTPPort int    `json:"acme_http_port"` // для HTTP-01, по умолчанию 80
	SSHAddr      string `json:"ssh_addr"`
	SSHUser      string `json:"ssh_user"`
	SSHPassword  string `json:"ssh_password"`
	SSHKeyFile   string `json:"ssh_key_file"`
	WGPort       int    `json:"wg_port"`

	SkipRemote bool `json:"skip_remote"` // только создать модель, без установки
	ApplyLocal bool `json:"apply_local"` // применить артефакты хаба на этой машине
}

type Report struct {
	NodeID     string   `json:"node_id"`
	TunnelID   string   `json:"tunnel_id"`
	Steps      []string `json:"steps"`
	Bootstrap  string   `json:"bootstrap_log,omitempty"`
	HostKey    string   `json:"host_key,omitempty"`
	LocalApply string   `json:"local_apply,omitempty"`
	MgmtAddr   string   `json:"mgmt_addr,omitempty"`
	CertPin    string   `json:"cert_pin,omitempty"`
}

// Run создаёт узел и туннель, ставит всё на удалённый хост и обновляет статус.
// Если задан NodeID — узел уже есть, меняются только файлы на нём.
func (s *Service) Run(req Request) (*Report, error) {
	if req.NodeID != "" {
		return s.reinstall(req)
	}
	if req.Addr == "" {
		return nil, fmt.Errorf("нужен адрес хоста (IP или домен)")
	}
	if req.Port == 0 {
		req.Port = 443
	}
	if req.WGPort == 0 {
		req.WGPort = 51820
	}
	if req.TunnelKind == "" {
		req.TunnelKind = model.TunnelWGReverse
	}
	if req.TLSBy == "" {
		if req.Domain != "" {
			req.TLSBy = "domain"
		} else {
			req.TLSBy = "ip"
		}
	}
	if req.SSHUser == "" {
		req.SSHUser = "root"
	}
	rep := &Report{}

	var hub model.Node
	st := s.Store.Snapshot()
	for _, n := range st.Nodes {
		if n.ID == req.HubNodeID {
			hub = n
		}
	}
	if hub.ID == "" && len(st.Nodes) > 0 {
		hub = st.Nodes[0]
	}
	if hub.ID == "" {
		return nil, fmt.Errorf("нет узла-хаба: сначала создай узел, с которого ставим")
	}

	nodeID := model.NewID("nd")
	tunnelID := model.NewID("tn")
	rep.NodeID, rep.TunnelID = nodeID, tunnelID

	sshAddr := req.SSHAddr
	if sshAddr == "" {
		sshAddr = req.Addr + ":22"
	}
	node := model.Node{
		ID: nodeID, Name: req.Name, Role: "exit",
		PublicAddr: fmt.Sprintf("%s:%d", req.Addr, req.Port),
		Core:       "xray",
		SSHAddr:    sshAddr, SSHUser: req.SSHUser,
		SSHAuth: pickAuth(req), SSHKeyFile: req.SSHKeyFile,
		Status: "unknown",
	}
	if node.Name == "" {
		node.Name = req.Addr
	}

	tun := model.Tunnel{
		ID: tunnelID, Name: "to-" + shortName(req.Addr), Kind: req.TunnelKind,
		FromNode: hub.ID, ToNode: nodeID, Enabled: true,
		ListenPort: req.WGPort, Keepalive: 25,
		EgressIface: "ens3", ForwardPolicy: true,
		Subnet: st.NextSubnet(), Mark: st.NextMark(),
	}
	if tun.Kind == model.TunnelVLESS {
		tun.ListenPortT = req.Port
	}

	// ключи и TLS
	switch tun.Kind {
	case model.TunnelWG, model.TunnelWGReverse:
		priv, pub, err := model.GenWGKeys()
		if err != nil {
			return nil, err
		}
		priv2, pub2, err := model.GenWGKeys()
		if err != nil {
			return nil, err
		}
		tun.FromKeyPriv, tun.FromKeyPub = priv, pub
		tun.ToKeyPriv, tun.ToKeyPub = priv2, pub2
	}
	var planExtra []bootstrap.File
	if tun.Kind != model.TunnelVLESS {
		rep.Steps = append(rep.Steps, "TLS: выбран "+req.TLSBy+
			", но для туннеля "+tun.Kind+" он не используется — сертификат понадобится инбаунду на выходном")
	}
	switch req.TLSBy {
	case "ip-le":
		ip := req.IP
		if ip == "" {
			ip = hostOnly(req.Addr)
		}
		if net.ParseIP(ip) == nil {
			return nil, fmt.Errorf("для сертификата Let's Encrypt нужен голый IP, получено %q", ip)
		}
		if req.ACMEEmail == "" {
			req.ACMEEmail = "admin@" + ip
		}
		tun.Security, tun.CertSource, tun.IP = "tls", "acmeip", ip
		tun.CertFile, tun.KeyFile = "/etc/revhub/tls/ip/fullchain.pem", "/etc/revhub/tls/ip/key.pem"
		rep.Steps = append(rep.Steps, "TLS: IP "+ip+" через Let's Encrypt (shortlived ~6 дней); "+
			"порт 80 должен быть свободен и доступен извне, продление — cron acme.sh")
	case "domain":
		if req.Domain == "" {
			return nil, fmt.Errorf("выбран TLS по домену — заполни поле «домен»")
		}
		if req.ACMEEmail == "" {
			req.ACMEEmail = "admin@" + req.Domain
		}
		tun.Security, tun.CertSource = "tls", "acme"
		tun.Domain = req.Domain
		tun.CertFile, tun.KeyFile = "/etc/revhub/tls/fullchain.pem", "/etc/revhub/tls/key.pem"
		rep.Steps = append(rep.Steps, "TLS: домен "+req.Domain+", сертификат выпустит acme.sh на узле")
	case "ip":
		ip := req.IP
		if ip == "" {
			ip = hostOnly(req.Addr)
		}
		dir, err := os.MkdirTemp("", "revhub-cert-*")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(dir)
		res, err := certs.SelfSigned(certs.Options{Hosts: []string{ip}, Days: 3650,
			Prefix: filepath.Join(dir, "server")})
		if err != nil {
			return nil, err
		}
		crt, err := os.ReadFile(res.CertFile)
		if err != nil {
			return nil, err
		}
		keyPEM, err := os.ReadFile(res.KeyFile)
		if err != nil {
			return nil, err
		}
		tun.Security, tun.CertSource, tun.IP = "tls", "selfsigned", ip
		tun.CertFile, tun.KeyFile, tun.Pin = "/etc/revhub/tls/server.crt", "/etc/revhub/tls/server.key", res.Pin
		planExtra = []bootstrap.File{
			{Path: "/etc/revhub/tls/server.crt", Data: crt, Mode: 0o644},
			{Path: "/etc/revhub/tls/server.key", Data: keyPEM, Mode: 0o600},
		}
		rep.CertPin = res.Pin
		rep.Steps = append(rep.Steps, "TLS: IP "+ip+", самоподписанный (CA такие не выдают), клиенту нужен пин")
	default:
		return nil, fmt.Errorf("TLS бывает по домену или по IP, получено %q", req.TLSBy)
	}

	// состояние: узел + туннель
	if err := s.Store.Patch(func(st *model.State) error {
		st.Nodes = append(st.Nodes, node)
		st.Tunnels = append(st.Tunnels, tun)
		return nil
	}); err != nil {
		return rep, fmt.Errorf("не смог сохранить узел и туннель: %w", err)
	}
	rep.Steps = append(rep.Steps, fmt.Sprintf("в модели: узел %s (%s), туннель %s (%s), подсеть %s, mark %d",
		node.Name, node.PublicAddr, tun.Name, tun.Kind, tun.Subnet, tun.Mark))

	// секрет SSH
	if req.SSHPassword != "" || req.SSHKeyFile != "" {
		sec := secrets.Secret{Password: req.SSHPassword}
		if req.SSHKeyFile != "" {
			b, err := os.ReadFile(req.SSHKeyFile)
			if err != nil {
				return rep, fmt.Errorf("ключ %s: %w", req.SSHKeyFile, err)
			}
			sec.PrivateKey = string(b)
		}
		if err := s.Secrets.Set(nodeID, sec); err != nil {
			return rep, err
		}
		rep.Steps = append(rep.Steps, "секрет SSH сохранён в secrets.json (0600)")
	}

	st = s.Store.Snapshot()

	// артефакты выходного и установка
	exitFiles, err := gen.Artifacts(st, nodeID)
	if err != nil {
		return rep, err
	}
	plan := bootstrap.Plan{
		Files:       planExtra,
		Artifacts:   exitFiles,
		InstallXray: tun.Kind == model.TunnelVLESS,
		InstallWG:   tun.Kind == model.TunnelWG || tun.Kind == model.TunnelWGReverse,
		XrayUnit:    xrayUnit,
		RemoteDir:   "/opt/revhub",
	}
	if req.TLSBy == "domain" {
		plan.ACMEDomain, plan.ACMEEmail, plan.ACMEDNS = req.Domain, req.ACMEEmail, req.ACMEDNS
	}
	if req.TLSBy == "ip-le" {
		plan.ACMEIP, plan.ACMEEmail, plan.ACMEHTTPPort = tun.IP, req.ACMEEmail, req.ACMEHTTPPort
	}
	if req.SkipRemote {
		rep.Steps = append(rep.Steps, "установка на хост пропущена (skip_remote)")
	} else {
		sec, _ := s.Secrets.Get(nodeID)
		target := sshx.Target{
			Addr: node.SSHAddr, User: node.SSHUser,
			Password: sec.Password, KeyPEM: []byte(sec.PrivateKey),
			HostKey: nodeKeyFromState(st, nodeID),
		}
		res, err := bootstrap.RunWith(s.opener(), target, plan, nil)
		if err != nil {
			_ = s.Store.Patch(func(st *model.State) error {
				markNode(st, nodeID, "dead", "", res.Text())
				return nil
			})
			return rep, fmt.Errorf("установка на %s: %w\n%s", node.SSHAddr, err, res.Text())
		}
		rep.Bootstrap = res.Text()
		rep.HostKey = res.HostKey
		_ = s.Store.Patch(func(st *model.State) error {
			n := findNode(st, nodeID)
			if n == nil {
				return nil
			}
			n.HostKey = res.HostKey // TOFU: следующий раз сверяем
			n.LastBootstrap = time.Now().UTC().Format(time.RFC3339)
			n.BootstrapLog = res.Text()
			n.Status = "alive"
			n.MgmtVia = "direct"
			return nil
		})
		rep.Steps = append(rep.Steps, "хост установлен и применён: "+res.XrayState+", wg: "+strings.Join(res.WGUp, ","))
	}

	// артефакты хаба (+ локальное применение, если панель и хаб — одна машина)
	hubFiles, err := gen.Artifacts(s.Store.Snapshot(), hub.ID)
	if err != nil {
		return rep, err
	}
	dir := filepath.Join(s.OutDir, hub.ID)
	man, err := gen.WriteArtifacts(dir, hubFiles)
	if err != nil {
		return rep, err
	}
	man.Node = hub.ID
	_ = os.WriteFile(filepath.Join(dir, "manifest.json"), man.JSON(), 0o640)
	rep.Steps = append(rep.Steps, "артефакты хаба обновлены: "+dir)

	if req.ApplyLocal {
		out, err := applyLocal(dir)
		rep.LocalApply = out
		if err != nil {
			rep.Steps = append(rep.Steps, "локальное применение хаба НЕ удалось: "+err.Error())
		} else {
			rep.Steps = append(rep.Steps, "хаб применён локально")
		}
	}
	return rep, nil
}

// reinstall ставит заново уже описанный узел: артефакты берутся из модели как есть.
func (s *Service) reinstall(req Request) (*Report, error) {
	rep := &Report{NodeID: req.NodeID}
	st := s.Store.Snapshot()
	var node model.Node
	for _, n := range st.Nodes {
		if n.ID == req.NodeID {
			node = n
		}
	}
	if node.ID == "" {
		return nil, fmt.Errorf("узел %q не найден", req.NodeID)
	}
	files, err := gen.Artifacts(st, node.ID)
	if err != nil {
		return rep, err
	}
	needWG, needXray := false, false
	for _, t := range st.Tunnels {
		if !t.Enabled || !t.Touches(node.ID) {
			continue
		}
		if t.Kind == model.TunnelVLESS {
			needXray = true
		} else {
			needWG = true
		}
	}
	for _, in := range st.Inbounds {
		if in.NodeID == node.ID && in.Enabled {
			needXray = true
		}
	}
	sec, _ := s.Secrets.Get(node.ID)
	res, err := bootstrap.RunWith(s.opener(), sshx.Target{
		Addr: node.SSHAddr, User: node.SSHUser,
		Password: sec.Password, KeyPEM: []byte(sec.PrivateKey), HostKey: node.HostKey,
	}, bootstrap.Plan{
		Artifacts: files, InstallXray: needXray, InstallWG: needWG,
		XrayUnit: xrayUnit, RemoteDir: "/opt/revhub",
	}, nil)
	if err != nil {
		_ = s.Store.Patch(func(st *model.State) error {
			markNode(st, node.ID, "dead", "", res.Text())
			return nil
		})
		return rep, fmt.Errorf("переустановка на %s: %w\n%s", node.SSHAddr, err, res.Text())
	}
	rep.Bootstrap = res.Text()
	rep.HostKey = res.HostKey
	_ = s.Store.Patch(func(st *model.State) error {
		n := findNode(st, node.ID)
		if n == nil {
			return nil
		}
		n.HostKey, n.Status = res.HostKey, "alive"
		n.LastBootstrap = time.Now().UTC().Format(time.RFC3339)
		n.BootstrapLog = res.Text()
		return nil
	})
	rep.Steps = append(rep.Steps, "узел переустановлен: "+res.XrayState)
	return rep, nil
}

func (s *Service) opener() bootstrap.Open {
	if s.Open != nil {
		return s.Open
	}
	return func(t sshx.Target) (bootstrap.Runner, error) { return sshx.Dial(t) }
}

// applyLocal применяет артефакты узла на этой машине (панель = хаб).
func applyLocal(dir string) (string, error) {
	if os.Geteuid() != 0 {
		return "", fmt.Errorf("нужен root: панель не может применить конфиг ядра")
	}
	cmd := exec.Command("bash", "apply.sh")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func markNode(st *model.State, id, status, via, log string) {
	if n := findNode(st, id); n != nil {
		n.Status = status
		if via != "" {
			n.MgmtVia = via
		}
		if log != "" {
			n.BootstrapLog = log
		}
	}
}

func findNode(st *model.State, id string) *model.Node {
	for i := range st.Nodes {
		if st.Nodes[i].ID == id {
			return &st.Nodes[i]
		}
	}
	return nil
}

func nodeKeyFromState(st model.State, id string) string {
	for _, n := range st.Nodes {
		if n.ID == id {
			return n.HostKey
		}
	}
	return ""
}

func pickAuth(r Request) string {
	if r.SSHKeyFile != "" {
		return "key"
	}
	return "password"
}

func shortName(addr string) string {
	addr = hostOnly(addr)
	addr = strings.ReplaceAll(addr, ".", "-")
	addr = strings.ReplaceAll(addr, ":", "-")
	if len(addr) > 20 {
		addr = addr[:20]
	}
	return addr
}

func hostOnly(s string) string {
	if i := strings.LastIndex(s, ":"); i > 0 && !strings.Contains(s[i+1:], ":") {
		return s[:i]
	}
	return s
}

const xrayUnit = `[Unit]
Description=Xray (revhub)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=2
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
`
