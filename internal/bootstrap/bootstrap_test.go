package bootstrap

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"revhub/internal/gen"
	"revhub/internal/model"
	"revhub/internal/sshx"
)

// fakeRunner — «узел» в памяти: записывает команды и файлы, отвечает по
// шаблонам. Сценарий установки проверяется без SSH-сервера.
type fakeRunner struct {
	cmds   []string
	files  map[string]string
	modes  map[string]os.FileMode
	uid    string
	noWG   bool
	failOn string
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{files: map[string]string{}, modes: map[string]os.FileMode{}, uid: "0"}
}

func (f *fakeRunner) HostKey() string { return "SHA256:fake" }

func (f *fakeRunner) Upload(path string, data []byte, mode os.FileMode) error {
	f.files[path] = string(data)
	f.modes[path] = mode
	return nil
}

func (f *fakeRunner) Run(cmd string) (string, error) {
	f.cmds = append(f.cmds, cmd)
	if f.failOn != "" && strings.Contains(cmd, f.failOn) {
		return "boom", fmt.Errorf("команда упала")
	}
	switch {
	case strings.HasPrefix(cmd, "id -u;"):
		return f.uid + "\nx86_64\nDebian GNU/Linux 12 (bookworm)\n", nil
	case strings.HasPrefix(cmd, "command -v wg-quick"):
		if f.noWG {
			return "", fmt.Errorf("не найдено")
		}
		return "/usr/sbin/wg-quick", nil
	case strings.HasPrefix(cmd, "command -v nft"):
		return "/usr/sbin/nft", nil
	case strings.HasPrefix(cmd, "command -v xray"):
		return "/usr/local/bin/xray", nil
	case strings.HasPrefix(cmd, "test -f /etc/systemd/system/xray.service"):
		return "", nil
	case strings.Contains(cmd, "apt-get install"):
		return "", nil
	case strings.Contains(cmd, "bash apply.sh"):
		return "применено", nil
	case strings.HasPrefix(cmd, "systemctl is-active xray"):
		return "active", nil
	case strings.HasPrefix(cmd, "wg show interfaces"):
		return "wg-eu", nil
	case strings.HasPrefix(cmd, "curl -s -m 8 https://ifconfig.me/ip"):
		return "198.51.100.7", nil
	}
	return "", fmt.Errorf("неизвестная команда: %s", cmd)
}

func openFake(f *fakeRunner) Open {
	return func(t sshx.Target) (Runner, error) { return f, nil }
}

func planFor(t *testing.T) Plan {
	t.Helper()
	st := model.Demo()
	files, err := gen.Artifacts(st, "exit-eu")
	if err != nil {
		t.Fatal(err)
	}
	return Plan{Artifacts: files, InstallXray: true, InstallWG: true, XrayUnit: "unit", RemoteDir: "/opt/revhub"}
}

func TestBootstrapFullFlow(t *testing.T) {
	f := newFakeRunner()
	res, err := RunWith(openFake(f), sshx.Target{Addr: "127.0.0.1:22"}, planFor(t), nil)
	if err != nil {
		t.Fatalf("bootstrap: %v\n%s", err, res.Text())
	}
	t.Log("\n" + res.Text())

	if res.XrayState != "active" {
		t.Errorf("xray state = %q", res.XrayState)
	}
	if len(res.WGUp) != 1 || res.WGUp[0] != "wg-eu" {
		t.Errorf("wg = %v", res.WGUp)
	}
	if res.EgressIP != "198.51.100.7" {
		t.Errorf("egress = %q", res.EgressIP)
	}
	if res.HostKey != "SHA256:fake" {
		t.Errorf("ключ хоста = %q", res.HostKey)
	}
	for _, name := range []string{"xray.json", "wg-eu.conf", "apply.sh", "rollback.sh"} {
		if _, ok := f.files["/opt/revhub/"+name]; !ok {
			t.Errorf("%s не загружен", name)
		}
	}
	if f.modes["/opt/revhub/wg-eu.conf"] != 0o600 {
		t.Errorf("права wg-конфига = %v", f.modes["/opt/revhub/wg-eu.conf"])
	}
	if f.modes["/opt/revhub/apply.sh"] != 0o700 {
		t.Errorf("права apply.sh = %v", f.modes["/opt/revhub/apply.sh"])
	}
	applied := false
	for _, c := range f.cmds {
		if strings.Contains(c, "bash apply.sh") {
			applied = true
		}
	}
	if !applied {
		t.Error("apply.sh не выполнялся")
	}
}

func TestBootstrapStopsWithoutRoot(t *testing.T) {
	f := newFakeRunner()
	f.uid = "1000"
	res, err := RunWith(openFake(f), sshx.Target{Addr: "x"}, planFor(t), nil)
	if err == nil {
		t.Fatal("без root должно падать")
	}
	if len(res.Steps) == 0 || !strings.Contains(res.Steps[0].Err, "root") {
		t.Fatalf("ступени = %+v", res.Steps)
	}
	if len(f.files) != 0 {
		t.Error("до проверки root ничего не должно загружаться")
	}
}

func TestBootstrapStopsWhenApplyFails(t *testing.T) {
	f := newFakeRunner()
	f.failOn = "bash apply.sh"
	res, err := RunWith(openFake(f), sshx.Target{Addr: "x"}, planFor(t), nil)
	if err == nil {
		t.Fatal("падение apply.sh должно останавливать установку")
	}
	last := res.Steps[len(res.Steps)-1]
	if last.Name != "применение" || last.Err == "" {
		t.Errorf("последняя ступень = %+v", last)
	}
}

// Если wireguard-tools нет — установщик обязан поставить пакеты, а не падать.
func TestBootstrapInstallsPackages(t *testing.T) {
	f := newFakeRunner()
	f.noWG = true
	if _, err := RunWith(openFake(f), sshx.Target{Addr: "x"}, planFor(t), nil); err != nil {
		t.Fatalf("установка: %v", err)
	}
	found := false
	for _, c := range f.cmds {
		if strings.Contains(c, "apt-get install -y -qq") && strings.Contains(c, "wireguard-tools") {
			found = true
		}
	}
	if !found {
		t.Error("пакеты не ставились, хотя wg-quick отсутствует")
	}
}

// Без WG-туннелей установщик не должен трогать пакеты и wg.
func TestBootstrapNoWGWhenNoTunnels(t *testing.T) {
	f := newFakeRunner()
	st := model.Demo()
	files, _ := gen.Artifacts(st, "hub")
	res, err := RunWith(openFake(f), sshx.Target{Addr: "x"},
		Plan{Artifacts: files, InstallXray: true, XrayUnit: "unit"}, nil)
	if err != nil {
		t.Fatalf("установка: %v", err)
	}
	for _, c := range f.cmds {
		if strings.HasPrefix(c, "command -v wg-quick") {
			t.Error("без WG-туннелей пакеты ставиться не должны")
		}
	}
	if res.XrayState != "active" {
		t.Errorf("xray state = %q", res.XrayState)
	}
}

func TestUploadCommandShape(t *testing.T) {
	cmd := sshx.UploadCommand("/etc/wireguard", "/etc/wireguard/wg-eu.conf", []byte("hello"), 0o600)
	if !strings.HasPrefix(cmd, "mkdir -p '/etc/wireguard' && : > '/etc/wireguard/wg-eu.conf' && ") {
		t.Errorf("начало команды: %s", cmd)
	}
	if !strings.HasSuffix(cmd, "chmod 600 '/etc/wireguard/wg-eu.conf'") {
		t.Errorf("конец команды: %s", cmd)
	}
	if !strings.Contains(cmd, "| base64 -d >> ") {
		t.Error("содержимое должно идти через base64")
	}
	if strings.Contains(cmd, "hello") {
		t.Error("открытое содержимое не должно попадать в командную строку")
	}
}
