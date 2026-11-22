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
	cmds      []string
	files     map[string]string
	modes     map[string]os.FileMode
	uid       string
	uidOutput *string
	noWG      bool
	failOn    string
	// xrayUnitOwn — на «узле» уже стоит наш юнит xray (читает наш конфиг).
	xrayUnitOwn bool
	// aptLocked — сколько первых вызовов apt ответят «занято» (cloud-init).
	aptLocked int
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
	case strings.HasPrefix(cmd, "uid=$(id -u)"):
		if f.uidOutput != nil {
			return *f.uidOutput, nil
		}
		return "__REVHUB_UID__=" + f.uid + "\n", nil
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
	case strings.Contains(cmd, "systemctl cat xray.service"):
		if f.xrayUnitOwn {
			return "1\n", nil
		}
		return "0\n", nil
	case strings.HasPrefix(cmd, "mkdir -p /etc/revhub && cp -a"):
		return "", nil
	case cmd == "systemctl daemon-reload":
		return "", nil
	case strings.Contains(cmd, "apt-get") && strings.Contains(cmd, "install -y -qq"):
		if f.aptLocked > 0 {
			f.aptLocked--
			return "E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 1532 (apt-get)\n" +
					"E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), is another process using it?",
				fmt.Errorf("DEBIAN_FRONTEND=noninteractive apt-get: exit status 100: E: Could not get lock")
		}
		return "", nil
	case strings.Contains(cmd, "bash apply.sh"):
		if strings.Contains(cmd, "| tail") {
			return "", fmt.Errorf("apply exit status masked by pipeline")
		}
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
	// Без своего юнита `systemctl restart xray` на узле падает с
	// «Unit xray.service not found» — юнит обязан уехать вместе с конфигом.
	if f.files["/etc/systemd/system/xray.service"] != "unit" {
		t.Errorf("юнит xray не установлен: %q", f.files["/etc/systemd/system/xray.service"])
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

type acmeDirRunner struct {
	*fakeRunner
	dir         string
	created     bool
	skipRenewal bool
}

func (r *acmeDirRunner) Run(cmd string) (string, error) {
	if cmd == "mkdir -p "+r.dir {
		r.created = true
		return "", nil
	}
	if strings.Contains(cmd, "--install-cert") {
		if !r.created {
			return "", fmt.Errorf("cannot touch %s/key.pem: No such file or directory", r.dir)
		}
		return "", nil
	}
	if strings.HasPrefix(cmd, "test -s /etc/revhub/tls/") {
		return "", fmt.Errorf("missing")
	}
	if strings.Contains(cmd, "--issue -d") && r.skipRenewal {
		if strings.Contains(cmd, "rc=$?") && strings.Contains(cmd, "-eq 2") {
			return "Skipping. Next renewal time", nil
		}
		return "Skipping. Next renewal time", fmt.Errorf("exit status 2")
	}
	if strings.HasPrefix(cmd, "test -x /root/.acme.sh/acme.sh") || strings.Contains(cmd, "--issue -d") || strings.Contains(cmd, "--set-default-ca") {
		return "", nil
	}
	if strings.HasPrefix(cmd, "ss -ltnu") {
		return "0", nil
	}
	return r.fakeRunner.Run(cmd)
}

func TestBootstrapACMECreatesDestinationDirectory(t *testing.T) {
	for _, tc := range []struct {
		name, dir string
		configure func(*Plan)
	}{
		{"domain", "/etc/revhub/tls", func(p *Plan) { p.ACMEDomain = "vpn.example.com" }},
		{"ip", "/etc/revhub/tls/ip", func(p *Plan) { p.ACMEIP = "198.51.100.1" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &acmeDirRunner{fakeRunner: newFakeRunner(), dir: tc.dir}
			p := planFor(t)
			tc.configure(&p)
			_, err := RunWith(func(sshx.Target) (Runner, error) { return r, nil }, sshx.Target{Addr: "test"}, p, nil)
			if err != nil {
				t.Fatalf("bootstrap: %v", err)
			}
		})
	}
}

func TestBootstrapACMERetryAfterRenewSkip(t *testing.T) {
	r := &acmeDirRunner{fakeRunner: newFakeRunner(), dir: "/etc/revhub/tls", skipRenewal: true}
	p := planFor(t)
	p.ACMEDomain = "vpn.example.com"
	_, err := RunWith(func(sshx.Target) (Runner, error) { return r, nil }, sshx.Target{Addr: "test"}, p, nil)
	if err != nil {
		t.Fatalf("retry after prior issue: %v", err)
	}
	if !r.created {
		t.Fatal("certificate was not installed")
	}
}

func TestBootstrapUIDWithBanner(t *testing.T) {
	f := newFakeRunner()
	banner := "\nWelcome to the server\n__REVHUB_UID__=0\n"
	f.uidOutput = &banner
	res, err := RunWith(openFake(f), sshx.Target{Addr: "x", User: "root"}, planFor(t), nil)
	if err != nil {
		t.Fatalf("root с приветствием: %v\n%s", err, res.Text())
	}
}

func TestBootstrapUIDMissing(t *testing.T) {
	f := newFakeRunner()
	empty := "\n"
	f.uidOutput = &empty
	_, err := RunWith(openFake(f), sshx.Target{Addr: "x", User: "root"}, planFor(t), nil)
	if err == nil || !strings.Contains(err.Error(), "не удалось определить UID") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(f.files) != 0 {
		t.Fatal("files uploaded without UID validation")
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
		if strings.Contains(c, "install -y -qq") && strings.Contains(c, "wireguard-tools") &&
			strings.Contains(c, "DPkg::Lock::Timeout") {
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

// Наш юнит уже стоит: не перезаписываем и не делаем лишний daemon-reload.
func TestBootstrapKeepsOwnXrayUnit(t *testing.T) {
	f := newFakeRunner()
	f.xrayUnitOwn = true
	res, err := RunWith(openFake(f), sshx.Target{Addr: "127.0.0.1:22"}, planFor(t), nil)
	if err != nil {
		t.Fatalf("bootstrap: %v\n%s", err, res.Text())
	}
	if _, ok := f.files["/etc/systemd/system/xray.service"]; ok {
		t.Error("юнит перезаписан без нужды")
	}
	for _, c := range f.cmds {
		if c == "systemctl daemon-reload" {
			t.Error("лишний daemon-reload")
		}
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
