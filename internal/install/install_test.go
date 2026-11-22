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

// acme.sh мог встать в $HOME/.acme.sh другого пользователя: ищем и там, а не
// только в /root — иначе установка падает на «no such file or directory».
func TestAcmeScriptFindsHome(t *testing.T) {
	home := t.TempDir()
	sh := filepath.Join(home, ".acme.sh", "acme.sh")
	if err := os.MkdirAll(filepath.Dir(sh), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sh, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	if got := acmeScript(""); got != sh {
		t.Errorf("acmeScript() = %q, ожидал %q", got, sh)
	}
}

// В dry-run ничего не устанавливаем и не ходим в сеть, но путь возвращаем —
// чтобы отчёт установки оставался читаемым.
func TestEnsureACMEDryRunNoNetwork(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // гарантируем, что acme.sh не найдётся
	r := &runner{dry: true, rep: &Report{}}
	sh, err := r.ensureACME(Options{EtcDir: t.TempDir(), UnitDir: t.TempDir()})
	if err != nil {
		t.Fatalf("dry-run не должен падать: %v", err)
	}
	if sh == "" {
		t.Error("dry-run должен вернуть путь к acme.sh по умолчанию")
	}
}

// Заглушка, HTML-ошибка или обрезанный файл не должны считаться acme.sh.
func TestValidACME(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.sh")
	body := "#!/usr/bin/env sh\n# LE_WORKING_DIR acme.sh\n" + strings.Repeat("# pad\n", 5000)
	if err := os.WriteFile(good, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	if !validACME(good) {
		t.Error("настоящий acme.sh не распознан")
	}
	small := filepath.Join(dir, "small.sh")
	os.WriteFile(small, []byte("#!/bin/sh\nLE_WORKING_DIR acme.sh\n"), 0o644)
	if validACME(small) {
		t.Error("обрезанный файл принят за acme.sh")
	}
	html := filepath.Join(dir, "err.html")
	os.WriteFile(html, []byte("<html>"+strings.Repeat("x", 30000)+"</html>"), 0o644)
	if validACME(html) {
		t.Error("HTML принят за acme.sh")
	}
	if validACME(filepath.Join(dir, "nope")) {
		t.Error("несуществующий файл принят за acme.sh")
	}
}

// Продление должно жить в своих юнитах: у acme.sh свой cron, а нам нужен
// предсказуемый путь и корректный LE_WORKING_DIR.
func TestAcmeTimerRendered(t *testing.T) {
	dir := t.TempDir()
	unitDir := t.TempDir()
	o := Options{EtcDir: dir, UnitDir: unitDir}
	sh := filepath.Join(dir, "acme", "acme.sh")
	r := &runner{dry: true, rep: &Report{}}
	if err := r.writeAcmeTimer(o, sh); err != nil {
		t.Fatalf("таймер: %v", err)
	}
	// в dry-run «install» не выполняется: файлы остаются в <EtcDir>/acme
	svc, err := os.ReadFile(filepath.Join(dir, "acme", "revhub-acme-renew.service"))
	if err != nil {
		t.Fatalf("нет service: %v", err)
	}
	if !strings.Contains(string(svc), "LE_WORKING_DIR="+filepath.Join(dir, "acme")) {
		t.Errorf("в service нет LE_WORKING_DIR: %s", svc)
	}
	if !strings.Contains(string(svc), sh+" --cron") {
		t.Errorf("в service неверный ExecStart: %s", svc)
	}
	tm, err := os.ReadFile(filepath.Join(dir, "acme", "revhub-acme-renew.timer"))
	if err != nil {
		t.Fatalf("нет timer: %v", err)
	}
	if !strings.Contains(string(tm), "OnCalendar=") || !strings.Contains(string(tm), "Persistent=true") {
		t.Errorf("таймер неполный: %s", tm)
	}
}

// Реальная загрузка acme.sh: по умолчанию пропускается, включается
// REVHUB_NET_TESTS=1 (нужна сеть).
func TestEnsureACMEDownloads(t *testing.T) {
	if os.Getenv("REVHUB_NET_TESTS") == "" {
		t.Skip("нужна сеть: REVHUB_NET_TESTS=1 go test ./internal/install/ -run Downloads")
	}
	dir := t.TempDir()
	o := Options{EtcDir: dir, UnitDir: filepath.Join(dir, "units")}
	r := &runner{rep: &Report{}}
	sh, err := r.ensureACME(o)
	if err != nil {
		t.Fatalf("скачивание acme.sh: %v", err)
	}
	if !validACME(sh) {
		t.Errorf("скачанное не похоже на acme.sh: %s", sh)
	}
	if st, err := os.Stat(sh); err != nil || st.Size() < 100000 {
		t.Errorf("acme.sh подозрительно мал: %v", err)
	}
	for _, f := range []string{"revhub-acme-renew.service", "revhub-acme-renew.timer"} {
		if _, err := os.Stat(filepath.Join(dir, "acme", f)); err != nil {
			t.Errorf("нет %s: %v", f, err)
		}
	}
}

// acme.sh не создаёт каталог назначения: installCert обязан сделать это сам.
func TestInstallCertCreatesDir(t *testing.T) {
	dir := t.TempDir()
	r := &runner{dry: true, rep: &Report{}}
	certDir := filepath.Join(dir, "tls", "ip") // ещё не существует
	if err := r.installCert("/bin/true", "203.0.113.7", certDir); err != nil {
		t.Fatalf("installCert: %v", err)
	}
	if st, err := os.Stat(certDir); err != nil || !st.IsDir() {
		t.Errorf("каталог не создан: %v", err)
	}
}

// Полный путь выпуска на IP с подставным acme.sh: проверяем аргументы, права на
// ключ и то, что ненулевой код возврата из --installcert не валит установку.
func TestAcmeIPWithStub(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "acme.log")
	sh := filepath.Join(dir, "acme", "acme.sh")
	if err := os.MkdirAll(filepath.Dir(sh), 0o755); err != nil {
		t.Fatal(err)
	}
	stub := `#!/bin/sh
printf '%s\n' "$*" >> "` + logPath + `"
case " $* " in
  *" --install-cert "*)
    fc=""; kf=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --fullchain-file) fc="$2"; shift 2 ;;
        --key-file) kf="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    [ -n "$fc" ] && printf 'CERT\n' > "$fc"
    [ -n "$kf" ] && printf 'KEY\n' > "$kf"
    exit 1
    ;;
esac
exit 0
`
	if err := os.WriteFile(sh, []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	o := Defaults()
	o.EtcDir, o.UnitDir = dir, filepath.Join(dir, "units")
	o.ACMEHTTPPort = 8089
	o.Email = "admin@example.com"
	r := &runner{rep: &Report{}}
	if err := r.acmeIP(o, "203.0.113.7"); err != nil {
		t.Fatalf("acmeIP: %v", err)
	}
	certDir := filepath.Join(dir, "tls", "ip")
	for _, f := range []string{"fullchain.pem", "key.pem"} {
		if st, err := os.Stat(filepath.Join(certDir, f)); err != nil || st.Size() == 0 {
			t.Errorf("%s не создан: %v", f, err)
		}
	}
	if st, err := os.Stat(filepath.Join(certDir, "key.pem")); err == nil && st.Mode().Perm() != 0o600 {
		t.Errorf("права ключа %v, ожидалось 0600", st.Mode().Perm())
	}
	log, _ := os.ReadFile(logPath)
	txt := string(log)
	for _, want := range []string{"--certificate-profile shortlived", "--install-cert", "--days 6", "--register-account"} {
		if !strings.Contains(txt, want) {
			t.Errorf("в вызовах acme.sh нет %q:\n%s", want, txt)
		}
	}
}
