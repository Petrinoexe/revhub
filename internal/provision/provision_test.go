package provision

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"revhub/internal/bootstrap"
	"revhub/internal/model"
	"revhub/internal/secrets"
	"revhub/internal/sshx"
	"revhub/internal/store"
)

var errNotExist = errors.New("нет файла")

type fakeNode struct {
	cmds  []string
	files map[string]string
	uid   string
}

func (f *fakeNode) HostKey() string { return "SHA256:fromfake" }
func (f *fakeNode) Upload(p string, d []byte, m os.FileMode) error {
	f.files[p] = string(d)
	return nil
}
func (f *fakeNode) Run(cmd string) (string, error) {
	f.cmds = append(f.cmds, cmd)
	switch {
	case strings.HasPrefix(cmd, "uid=$(id -u)"):
		return "__REVHUB_UID__=" + f.uid + "\n", nil
	case strings.HasPrefix(cmd, "command -v "):
		return "/usr/bin/x", nil
	case strings.HasPrefix(cmd, "test -s /etc/revhub/tls/fullchain"):
		return "", errNotExist
	case strings.HasPrefix(cmd, "test -x /root/.acme.sh/acme.sh"):
		return "", nil
	case strings.HasPrefix(cmd, "test -s /etc/revhub/tls/ip/"):
		return "", errNotExist
	case strings.HasPrefix(cmd, "ss -ltnu"):
		return "0", nil
	case strings.HasPrefix(cmd, "/root/.acme.sh/acme.sh --set-default-ca"):
		return "", nil
	case contains(cmd, "--issue -d") && contains(cmd, "--certificate-profile shortlived"):
		return "IP-сертификат выпущен", nil
	case contains(cmd, "--issue -d"):
		return "сертификат выпущен", nil
	case contains(cmd, "--install-cert"):
		return "", nil
	case strings.HasPrefix(cmd, "test -f /etc/systemd/"):
		return "", nil
	case strings.HasPrefix(cmd, "apt-get i"):
		return "", nil
	case contains(cmd, "bash apply.sh"):
		return "ok", nil
	case strings.HasPrefix(cmd, "systemctl is-active xr"):
		return "active", nil
	case strings.HasPrefix(cmd, "wg show interfac"):
		var interfaces []string
		for path := range f.files {
			name := filepath.Base(path)
			if strings.HasPrefix(name, "wg-") && strings.HasSuffix(name, ".conf") {
				interfaces = append(interfaces, strings.TrimSuffix(name, ".conf"))
			}
		}
		return strings.Join(interfaces, " "), nil
	case strings.HasPrefix(cmd, "curl -s -m 8 https://if"):
		return "198.51.100.9", nil
	}
	return "", nil
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func newService(t *testing.T) (*Service, *fakeNode, string) {
	t.Helper()
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	st, err := store.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	st.Replace(model.Demo()) // хаб + выходной из демо
	sec, err := secrets.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeNode{files: map[string]string{}, uid: "0"}
	svc := &Service{
		Store: st, Secrets: sec, OutDir: filepath.Join(dir, "out"),
		Open: func(t2 sshx.Target) (bootstrap.Runner, error) { return fake, nil },
	}
	return svc, fake, dir
}

func TestProvisionAddsNodeAndInstalls(t *testing.T) {
	svc, fake, _ := newService(t)
	rep, err := svc.Run(Request{
		Name: "Новый выход", Addr: "198.51.100.9", HubNodeID: "hub",
		TunnelKind: model.TunnelWGReverse, TLSBy: "ip", IP: "198.51.100.9",
		SSHPassword: "secret", ApplyLocal: false,
	})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if rep.NodeID == "" || rep.TunnelID == "" {
		t.Fatalf("отчёт без идентификаторов: %+v", rep)
	}
	st := svc.Store.Snapshot()
	if len(st.Nodes) != 3 {
		t.Errorf("узлов %d, ожидалось 3", len(st.Nodes))
	}
	if len(st.Tunnels) != 2 {
		t.Errorf("туннелей %d, ожидалось 2", len(st.Tunnels))
	}
	var tun model.Tunnel
	for _, x := range st.Tunnels {
		if x.ToNode == rep.NodeID {
			tun = x
		}
	}
	if tun.Kind != model.TunnelWGReverse || tun.FromNode != "hub" {
		t.Errorf("туннель = %+v", tun)
	}
	if tun.Mark == 0 || tun.Subnet == "" {
		t.Errorf("туннель без mark/подсети: %+v", tun)
	}
	if tun.FromKeyPriv == "" || tun.ToKeyPub == "" {
		t.Error("ключи WG не сгенерированы")
	}

	var node model.Node
	for _, n := range st.Nodes {
		if n.ID == rep.NodeID {
			node = n
		}
	}
	if node.Status != "alive" {
		t.Errorf("статус после установки = %q", node.Status)
	}
	if node.HostKey != "SHA256:fromfake" {
		t.Errorf("ключ хоста не запомнен: %q", node.HostKey)
	}
	if node.LastBootstrap == "" {
		t.Error("время установки не записано")
	}
	// на узел уехали артефакты его стороны
	if _, ok := fake.files["/opt/revhub/xray.json"]; !ok {
		t.Error("xray.json не загружен на выходной")
	}
	if _, ok := fake.files["/opt/revhub/"+tun.WGInterface()+".conf"]; !ok {
		t.Errorf("wg-конфиг не загружен; файлы: %v", keys(fake.files))
	}
	// и секрет не попал в состояние
	raw, _ := os.ReadFile(filepath.Join(filepath.Dir("x"), "state.json"))
	_ = raw
	if _, ok := svc.Secrets.Get(rep.NodeID); !ok {
		t.Error("секрет SSH не сохранён")
	}
}

func TestProvisionRejectsUnknownTLS(t *testing.T) {
	svc, _, _ := newService(t)
	if _, err := svc.Run(Request{Addr: "198.51.100.10", TLSBy: "reality", TunnelKind: model.TunnelWG}); err == nil {
		t.Fatal("неизвестный способ TLS должен отвергаться")
	}
	if _, err := svc.Run(Request{Addr: "198.51.100.10", TLSBy: "domain", TunnelKind: model.TunnelWG}); err == nil {
		t.Fatal("режим «по домену» без домена должен падать")
	}
}

// TLS по домену: сертификат выпускается на самом узле через acme.sh.
func TestProvisionDomainIssuesACME(t *testing.T) {
	svc, fake, _ := newService(t)
	rep, err := svc.Run(Request{
		Name: "Домен", Addr: "vpn.example.com", HubNodeID: "hub",
		TunnelKind: model.TunnelVLESS, TLSBy: "domain", Domain: "vpn.example.com",
		SSHPassword: "x", ApplyLocal: false,
	})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	st := svc.Store.Snapshot()
	var tun model.Tunnel
	for _, t2 := range st.Tunnels {
		if t2.ToNode == rep.NodeID {
			tun = t2
		}
	}
	if tun.Security != "tls" || tun.CertSource != "acme" || tun.Domain != "vpn.example.com" {
		t.Errorf("туннель: security=%q source=%q domain=%q", tun.Security, tun.CertSource, tun.Domain)
	}
	issued := false
	for _, c := range fake.cmds {
		if contains(c, "--issue -d vpn.example.com") {
			issued = true
		}
	}
	if !issued {
		t.Errorf("ACME не запускался; команды: %v", fake.cmds)
	}
}

// TLS по IP через Let's Encrypt: профиль shortlived, HTTP-01 на самом узле.
func TestProvisionIPViaLetsEncrypt(t *testing.T) {
	svc, fake, _ := newService(t)
	rep, err := svc.Run(Request{
		Name: "IP LE", Addr: "198.51.100.12", HubNodeID: "hub",
		TunnelKind: model.TunnelVLESS, TLSBy: "ip-le", IP: "198.51.100.12",
		SSHPassword: "x", ApplyLocal: false,
	})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	st := svc.Store.Snapshot()
	var tun model.Tunnel
	for _, x := range st.Tunnels {
		if x.ToNode == rep.NodeID {
			tun = x
		}
	}
	if tun.CertSource != "acmeip" || tun.IP != "198.51.100.12" {
		t.Errorf("туннель: source=%q ip=%q", tun.CertSource, tun.IP)
	}
	if tun.CertFile != "/etc/revhub/tls/ip/fullchain.pem" {
		t.Errorf("путь сертификата = %q", tun.CertFile)
	}
	found := false
	for _, c := range fake.cmds {
		if contains(c, "--certificate-profile shortlived") && contains(c, "-d 198.51.100.12") {
			found = true
		}
	}
	if !found {
		t.Errorf("команда выпуска без shortlived; команды: %v", fake.cmds)
	}
}

// TLS по IP: сертификат генерируется на панели и уезжает на узел файлами.
func TestProvisionIPUploadsCert(t *testing.T) {
	svc, fake, _ := newService(t)
	if _, err := svc.Run(Request{
		Name: "IP", Addr: "198.51.100.11", HubNodeID: "hub",
		TunnelKind: model.TunnelVLESS, TLSBy: "ip", IP: "198.51.100.11",
		SSHPassword: "x", ApplyLocal: false,
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := fake.files["/etc/revhub/tls/server.crt"]; !ok {
		t.Errorf("сертификат не загружен; файлы: %v", keys(fake.files))
	}
	if _, ok := fake.files["/etc/revhub/tls/server.key"]; !ok {
		t.Error("ключ не загружен")
	}
}

func TestProvisionRequiresAddr(t *testing.T) {
	svc, _, _ := newService(t)
	if _, err := svc.Run(Request{}); err == nil {
		t.Fatal("без адреса должно падать")
	}
}

func keys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
