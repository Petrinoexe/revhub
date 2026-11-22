package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"revhub/internal/certs"
	"revhub/internal/model"
)

// Полная установка в песочницу: системные команды не выполняются (DryRun),
// но файлы пишутся — по ним и проверяем.
func runSandbox(t *testing.T, mode string) (*Report, Options, string) {
	t.Helper()
	dir := t.TempDir()
	o := Defaults()
	o.Prefix = filepath.Join(dir, "usr-local")
	o.EtcDir = filepath.Join(dir, "etc-revhub")
	o.StateDir = filepath.Join(dir, "var-lib-revhub")
	o.Host = "203.0.113.5"
	o.Mode = mode
	o.DryRun = true
	o.NoStart = true
	o.NoApply = true
	o.SkipPkgs = true
	o.PanelOnly = false // тесты ниже проверяют стартовый инбаунд и ссылку клиента
	rep, err := Run(o)
	if err != nil {
		t.Fatalf("установка в песочницу: %v", err)
	}
	return rep, o, dir
}

func TestInstallTLSIP(t *testing.T) {
	rep, o, _ := runSandbox(t, TLSIP)
	if rep.Pin == "" {
		t.Error("для режима ip должен быть пин сертификата")
	}
	if rep.ClientLink == "" || !strings.HasPrefix(rep.ClientLink, "vless://") {
		t.Errorf("ссылка клиента не собрана: %q", rep.ClientLink)
	}
	if !strings.Contains(rep.ClientLink, "security=tls") {
		t.Errorf("в ссылке нет security=tls: %s", rep.ClientLink)
	}
	if !strings.Contains(rep.ClientLink, "allowInsecure=1") {
		t.Errorf("для самоподписанного сертификата нужен allowInsecure: %s", rep.ClientLink)
	}
	if rep.SubURL == "" {
		t.Error("не собран URL подписки")
	}

	// состояние валидно и содержит tls-инбаунд с путями к сертификату
	raw, err := os.ReadFile(filepath.Join(o.EtcDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "cert_file") {
		t.Error("в состоянии нет cert_file")
	}
	st := model.State{}
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	if err := st.Validate(); err != nil {
		t.Fatalf("состояние из установщика невалидно: %v", err)
	}
	in := st.Inbounds[0]
	if in.Security != "tls" || !in.SelfSigned {
		t.Errorf("инбаунд: security=%q self_signed=%v", in.Security, in.SelfSigned)
	}
	if _, err := os.Stat(in.CertFile); err != nil {
		t.Errorf("сертификат не создан: %v", err)
	}
	if _, err := os.Stat(in.KeyFile); err != nil {
		t.Errorf("ключ не создан: %v", err)
	}

	// файл с паролем админа — 0600, и пароль не в состоянии
	pf := rep.PasswordFile
	info, err := os.Stat(pf)
	if err != nil {
		t.Fatalf("нет файла пароля: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("права файла пароля %v, ожидалось 0600", info.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(o.EtcDir, "credentials.json")); err != nil {
		t.Error("credentials.json не создан")
	}

	// юнит ссылается на реальные пути
	unit, err := os.ReadFile(filepath.Join(o.EtcDir, "revhub.service"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ExecStart=", "serve --state", "Restart=on-failure", "PrivateTmp=true"} {
		if !strings.Contains(string(unit), want) {
			t.Errorf("в юните нет %q", want)
		}
	}
	// артефакты отрендерены
	if rep.ArtifactsDir == "" {
		t.Fatal("артефакты не отрендерены")
	}
	if _, err := os.Stat(filepath.Join(rep.ArtifactsDir, "xray.json")); err != nil {
		t.Error("xray.json не отрендерен")
	}
}

func TestInstallReality(t *testing.T) {
	rep, o, _ := runSandbox(t, TLSReality)
	if rep.Pin != "" {
		t.Error("у reality нет сертификата и пина")
	}
	if !strings.Contains(rep.ClientLink, "security=reality") {
		t.Errorf("ссылка должна быть reality: %s", rep.ClientLink)
	}
	if !strings.Contains(rep.ClientLink, "pbk=") {
		t.Errorf("в reality-ссылке нет публичного ключа: %s", rep.ClientLink)
	}
	unit, _ := os.ReadFile(filepath.Join(o.EtcDir, "revhub.service"))
	if strings.Contains(string(unit), "--tls-cert") {
		t.Error("для reality панель не должна поднимать TLS: сертификата нет")
	}
}

// Самоподписанный сертификат на домене должен распознаваться по файлу, а не по
// флагу режима: иначе клиент получит ссылку без allowInsecure и не подключится.
func TestDomainSelfSignedDetected(t *testing.T) {
	src := t.TempDir()
	res, err := certs.SelfSigned(certs.Options{Hosts: []string{"vpn.example.com"},
		Prefix: filepath.Join(src, "vpn")})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	o := Defaults()
	o.Prefix, o.EtcDir, o.StateDir = filepath.Join(dir, "p"), filepath.Join(dir, "e"), filepath.Join(dir, "s")
	o.Host, o.Mode, o.Domain = "vpn.example.com", TLSDomain, "vpn.example.com"
	o.CertFile, o.KeyFile = res.CertFile, res.KeyFile
	o.DryRun, o.NoStart, o.NoApply, o.SkipPkgs = true, true, true, true
	o.PanelOnly = false
	rep, err := Run(o)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rep.ClientLink, "allowInsecure=1") {
		t.Errorf("самоподписанный домен: нет allowInsecure в ссылке: %s", rep.ClientLink)
	}
	if rep.Pin != res.Pin {
		t.Errorf("пин %q не совпал с сертификатом %q", rep.Pin, res.Pin)
	}
}

func TestInstallIdempotent(t *testing.T) {
	dir := t.TempDir()
	o := Defaults()
	o.Prefix = filepath.Join(dir, "p")
	o.EtcDir = filepath.Join(dir, "e")
	o.StateDir = filepath.Join(dir, "s")
	o.Host = "198.51.100.1"
	o.Mode = TLSIP
	o.DryRun, o.NoStart, o.NoApply, o.SkipPkgs = true, true, true, true
	if _, err := Run(o); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(filepath.Join(o.EtcDir, "state.json"))
	rep2, err := Run(o)
	if err != nil {
		t.Fatalf("повторная установка упала: %v", err)
	}
	second, _ := os.ReadFile(filepath.Join(o.EtcDir, "state.json"))
	if string(first) != string(second) {
		t.Error("повторная установка перетёрла состояние")
	}
	if rep2.PasswordFile != "(пароль уже был задан ранее)" {
		t.Errorf("пароль пересоздался: %q", rep2.PasswordFile)
	}
}

func TestInstallDomainNeedsCertOrACME(t *testing.T) {
	dir := t.TempDir()
	o := Defaults()
	o.Prefix, o.EtcDir, o.StateDir = filepath.Join(dir, "p"), filepath.Join(dir, "e"), filepath.Join(dir, "s")
	o.Host, o.Mode, o.Domain = "vpn.example.com", TLSDomain, ""
	o.DryRun, o.NoStart, o.NoApply, o.SkipPkgs = true, true, true, true
	if _, err := Run(o); err == nil {
		t.Fatal("без домена режим domain должен падать")
	}
	o.Domain, o.ACME = "vpn.example.com", "off"
	if _, err := Run(o); err == nil {
		t.Fatal("без --cert/--key и без acme режим domain должен падать")
	}
}

// Установка по умолчанию ставит пустую панель: только карточка хоста, все
// списки — пустые массивы (не null), ссылок клиента и подписки нет.
func TestInstallPanelOnlyEmpty(t *testing.T) {
	dir := t.TempDir()
	o := Defaults()
	o.Prefix, o.EtcDir, o.StateDir = filepath.Join(dir, "p"), filepath.Join(dir, "e"), filepath.Join(dir, "s")
	o.Host, o.Mode = "203.0.113.9", TLSIP
	o.DryRun, o.NoStart, o.NoApply, o.SkipPkgs = true, true, true, true
	rep, err := Run(o)
	if err != nil {
		t.Fatalf("установка: %v", err)
	}
	if rep.PanelURL == "" {
		t.Error("пустая панель: не собран URL панели")
	}
	if rep.ClientLink != "" || rep.SubURL != "" {
		t.Errorf("пустая панель не должна иметь клиента: link=%q sub=%q", rep.ClientLink, rep.SubURL)
	}
	raw, err := os.ReadFile(filepath.Join(o.EtcDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"inbounds": []`, `"tunnels": []`, `"clients": []`, `"routes": []`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("в state.json нет %s", want)
		}
	}
	st := model.State{}
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	if len(st.Nodes) != 1 {
		t.Errorf("узлов %d, ожидался 1 (карточка этого хоста)", len(st.Nodes))
	}
	if err := st.Validate(); err != nil {
		t.Errorf("состояние невалидно: %v", err)
	}
	if !strings.Contains(st.Nodes[0].PublicAddr, "203.0.113.9") {
		t.Errorf("public_addr узла: %q", st.Nodes[0].PublicAddr)
	}
}

func TestPanelURL(t *testing.T) {
	o := Defaults()
	if got := panelURL(o); got != "http://127.0.0.1:2096" {
		t.Errorf("URL панели = %q", got)
	}
	o.PanelAddr, o.PanelTLS = "0.0.0.0:2096", true
	if got := panelURL(o); got != "https://127.0.0.1:2096" {
		t.Errorf("URL панели = %q", got)
	}
}
