// Package install — установщик «как у x-ui»: ставит бинарь, ядро, wireguard,
// сервис, генерит админа, настраивает TLS. Панель ставится пустой: инбаунды,
// туннели, клиенты и правила добавляются в UI.
//
// Принцип: каждая ступень отдельно, идемпотентно и с отчётом. Ступень, которая
// упала, не тянет за собой остальные: установщик останавливается и говорит, что
// именно не сделано.
package install

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"revhub/internal/auth"
	"revhub/internal/certs"
	"revhub/internal/gen"
	"revhub/internal/model"
	"revhub/internal/sub"
)

// Режимы TLS.
const (
	TLSReality = "reality" // без сертификата, работает на голом IP
	TLSDomain  = "domain"  // домен + ACME (acme.sh) или свои файлы
	TLSIP      = "ip"      // самоподписанный на IP + пиннинг у клиента
	TLSIPLE    = "ip-le"   // Let's Encrypt на голый IP (shortlived, ~6 дней)
	TLSNone    = "none"
)

type Options struct {
	Prefix       string // /usr/local
	EtcDir       string // /etc/revhub
	StateDir     string // /var/lib/revhub
	PanelAddr    string
	PanelTLS     bool
	Host         string // публичный IP или домен: и в ссылки, и в SAN
	Mode         string // reality | domain | ip | none
	Domain       string
	Email        string
	ACME         string // http | dns | off
	ACMEDNS      string // dns_cf, dns_ovh... для --acme=dns
	ACMEHTTPPort int    // для HTTP-01 (по умолчанию 80)
	CertFile     string // если сертификат уже есть
	KeyFile      string
	Port         int
	AdminUser    string
	OutDir       string
	UnitDir      string // куда класть юниты (по умолчанию /etc/systemd/system)
	PanelOnly    bool   // только панель: без инбаунда, клиентов и правил
	DryRun       bool   // не выполнять системные команды, но файлы писать
	NoStart      bool
	NoApply      bool
	SkipPkgs     bool
	PrintPass    bool
}

type Step struct {
	Name    string `json:"name"`
	Detail  string `json:"detail"`
	Skipped bool   `json:"skipped,omitempty"`
	Err     string `json:"err,omitempty"`
}

type Report struct {
	Steps        []Step `json:"steps"`
	PanelURL     string `json:"panel_url"`
	AdminUser    string `json:"admin_user"`
	PasswordFile string `json:"password_file"`
	Password     string `json:"password,omitempty"` // только при PrintPass
	NodeID       string `json:"node_id"`
	CertFile     string `json:"cert_file,omitempty"`
	Pin          string `json:"pin,omitempty"`
	ClientLink   string `json:"client_link,omitempty"`
	SubURL       string `json:"sub_url,omitempty"`
	ArtifactsDir string `json:"artifacts_dir,omitempty"`
}

func Defaults() Options {
	return Options{
		Prefix: "/usr/local", EtcDir: "/etc/revhub", StateDir: "/var/lib/revhub",
		PanelAddr: "127.0.0.1:2096", Mode: TLSIP, ACME: "http",
		Port: 443, AdminUser: "admin", UnitDir: "/etc/systemd/system", PanelOnly: true,
	}
}

func Run(o Options) (*Report, error) {
	o = withDefaults(o)
	rep := &Report{AdminUser: o.AdminUser, NodeID: "node-1"}
	r := &runner{dry: o.DryRun, rep: rep}

	// root нужен только для системных каталогов и systemd: установка в
	// собственный префикс (тесты, домашняя папка) допустима и без него.
	if !o.DryRun && os.Geteuid() != 0 && !writableAncestor(o.EtcDir) {
		return rep, fmt.Errorf("нужен root: установка пишет в %s и управляет юнитами", o.EtcDir)
	}

	// 1. каталоги
	r.step("каталоги", func() (string, error) {
		for _, d := range []string{o.EtcDir, filepath.Join(o.EtcDir, "tls"), o.StateDir,
			filepath.Join(o.StateDir, "out"), filepath.Join(o.Prefix, "bin")} {
			if err := os.MkdirAll(d, 0o750); err != nil {
				return "", err
			}
		}
		return fmt.Sprintf("%s, %s, %s", o.EtcDir, o.StateDir, filepath.Join(o.Prefix, "bin")), nil
	})

	// 2. бинарь панели
	r.step("бинарь revhub", func() (string, error) {
		self, err := os.Executable()
		if err != nil {
			return "", err
		}
		dst := filepath.Join(o.Prefix, "bin", "revhub")
		if samePath(self, dst) {
			return "уже на месте: " + dst, nil
		}
		if err := copyFile(self, dst, 0o755); err != nil {
			return "", err
		}
		return dst, nil
	})

	// 3. ядро xray
	xrayPath := filepath.Join(o.Prefix, "bin", "xray")
	r.step("ядро xray", func() (string, error) {
		if p, err := lookXray(o.Prefix); err == nil {
			xrayPath = p
			return "найдено: " + p, nil
		}
		if o.DryRun {
			return "будет скачано в " + xrayPath, nil
		}
		if err := downloadXray(xrayPath); err != nil {
			return "", err
		}
		return "скачано: " + xrayPath, nil
	})

	// 4. системные пакеты (нужны для туннелей)
	r.step("пакеты wireguard/nftables", func() (string, error) {
		if o.SkipPkgs {
			return "пропущено флагом --skip-packages", errSkip
		}
		missing := []string{}
		for _, bin := range []string{"wg", "wg-quick", "nft"} {
			if _, err := lookPath(bin); err != nil {
				missing = append(missing, bin)
			}
		}
		if len(missing) == 0 {
			return "уже стоят: wg, wg-quick, nft", nil
		}
		if err := r.run("apt-get", "update", "-qq"); err != nil {
			return "", err
		}
		if err := r.run("apt-get", "install", "-y", "-qq", "wireguard-tools", "nftables"); err != nil {
			return "", err
		}
		return "поставлены: wireguard-tools, nftables", nil
	})

	// 5. TLS
	tlsCfg, err := setupTLS(o, r)
	if err != nil {
		return rep, err
	}
	rep.CertFile, rep.Pin = tlsCfg.certFile, tlsCfg.pin

	// 6. состояние + админ + первый клиент
	st, err := writeState(o, tlsCfg, rep)
	if err != nil {
		return rep, err
	}

	// 7. юниты
	r.step("systemd-юниты", func() (string, error) {
		if err := os.MkdirAll(o.UnitDir, 0o755); err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(o.EtcDir, "revhub.service"),
			[]byte(revhubUnit(o, xrayPath)), 0o644); err != nil {
			return "", err
		}
		var made []string
		if _, err := lookPath("xray"); err != nil {
			if err := os.WriteFile(filepath.Join(o.EtcDir, "xray.service"),
				[]byte(xrayUnit(xrayPath)), 0o644); err != nil {
				return "", err
			}
			if err := r.run("install", "-m", "644", filepath.Join(o.EtcDir, "xray.service"),
				filepath.Join(o.UnitDir, "xray.service")); err != nil {
				return "", err
			}
			made = append(made, "xray.service")
		}
		unit := filepath.Join(o.EtcDir, "revhub.service")
		if err := r.run("install", "-m", "644", unit, filepath.Join(o.UnitDir, "revhub.service")); err != nil {
			return "", err
		}
		made = append(made, "revhub.service")
		if o.UnitDir == "/etc/systemd/system" {
			if err := r.run("systemctl", "daemon-reload"); err != nil {
				return "", err
			}
		}
		return strings.Join(made, ", "), nil
	})

	// 8. рендер артефактов и первое применение
	r.step("артефакты узла", func() (string, error) {
		files, err := gen.Artifacts(st, rep.NodeID)
		if err != nil {
			return "", err
		}
		dir := filepath.Join(o.StateDir, "out", rep.NodeID)
		man, err := gen.WriteArtifacts(dir, files)
		if err != nil {
			return "", err
		}
		man.Node = rep.NodeID
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), man.JSON(), 0o640); err != nil {
			return "", err
		}
		rep.ArtifactsDir = dir
		return fmt.Sprintf("%d файла в %s", len(files), dir), nil
	})

	r.step("включение сервисов", func() (string, error) {
		if o.DryRun {
			return "пропущено: --dry-run не трогает systemd", errSkip
		}
		if o.NoStart || o.NoApply {
			return "пропущено флагами --no-start/--no-apply", errSkip
		}
		if err := r.run("systemctl", "enable", "--now", "xray"); err != nil {
			// xray мог быть поставлен снаружи со своим юнитом — не валим установку
			rep.Steps = append(rep.Steps, Step{Name: "  примечание", Detail: "systemd: " + err.Error()})
		}
		if err := r.run("systemctl", "enable", "--now", "revhub"); err != nil {
			return "", err
		}
		return "xray + revhub включены", nil
	})

	rep.PanelURL = panelURL(o)
	if len(st.Clients) > 0 { // панель ставится пустой — клиента может не быть
		rep.SubURL = "/sub/" + st.Clients[0].SubToken
		if links := sub.Links(st, st.Clients[0]); len(links) > 0 {
			rep.ClientLink = links[0]
		}
	}
	return rep, nil
}

// ---------------------------------------------------------------- TLS

type tlsCfg struct {
	mode       string
	selfIssued bool
	certFile   string
	keyFile    string
	pin        string
	privateKey string
	publicKey  string
	shortID    string
	sni        string
	dest       string
}

func setupTLS(o Options, r *runner) (*tlsCfg, error) {
	cfg := &tlsCfg{mode: o.Mode}
	tlsDir := filepath.Join(o.EtcDir, "tls")

	switch o.Mode {
	case TLSNone:
		r.rep.Steps = append(r.rep.Steps, Step{Name: "TLS", Skipped: true,
			Detail: "выключен: VLESS без TLS виден DPI, годится только для теста"})
		return cfg, nil

	case TLSReality:
		priv, pub, err := model.GenRealityKeys()
		if err != nil {
			return nil, err
		}
		sni := o.Domain
		if sni == "" {
			sni = "www.microsoft.com"
		}
		cfg.sni, cfg.dest = sni, sni+":443"
		cfg.privateKey, cfg.publicKey, cfg.shortID = priv, pub, model.GenShortID()
		r.rep.Steps = append(r.rep.Steps, Step{Name: "TLS: reality",
			Detail: "маскировка под " + sni + ", сертификат не нужен и не выписывается"})
		return cfg, nil

	case TLSIP:
		if o.Host == "" {
			return nil, fmt.Errorf("для TLS на IP нужен --host <ip>")
		}
		prefix := filepath.Join(tlsDir, "server")
		res, err := certs.SelfSigned(certs.Options{Hosts: []string{o.Host}, Days: 3650, Prefix: prefix})
		if err != nil {
			return nil, err
		}
		cfg.certFile, cfg.keyFile, cfg.pin = res.CertFile, res.KeyFile, res.Pin
		cfg.sni = o.Host
		r.rep.Steps = append(r.rep.Steps, Step{Name: "TLS: самоподписанный на IP",
			Detail: fmt.Sprintf("%s, SAN=%s, до %s, пин %s", res.CertFile, o.Host,
				res.NotAfter.Format("2006-01-02"), short(res.Pin))})
		r.rep.Steps = append(r.rep.Steps, Step{Name: "  внимание",
			Detail: "публичные CA не выдают сертификаты на голый IP: клиенту нужен allowInsecure или закреплённый пин"})
		return cfg, nil

	case TLSIPLE:
		ip := o.Host
		if ip == "" {
			return nil, fmt.Errorf("для --tls ip-le нужен --host <ip>")
		}
		cfg.sni = ip
		cfg.certFile = filepath.Join(tlsDir, "ip", "fullchain.pem")
		cfg.keyFile = filepath.Join(tlsDir, "ip", "key.pem")
		if err := r.acmeIP(o, ip); err != nil {
			return nil, err
		}
		if o.DryRun {
			r.rep.Steps = append(r.rep.Steps, Step{Name: "TLS: Let's Encrypt на IP",
				Detail: "выпуск пропущен (--dry-run): будет acme.sh --certificate-profile shortlived"})
			return cfg, nil
		}
		info, err := certs.Describe(cfg.certFile)
		if err != nil {
			return nil, err
		}
		cfg.pin = info.Pin
		r.rep.Steps = append(r.rep.Steps, Step{Name: "TLS: Let's Encrypt на IP",
			Detail: fmt.Sprintf("%s, до %s (shortlived, продление — cron acme.sh)",
				ip, info.NotAfter.Format("2006-01-02 15:04"))})
		return cfg, nil

	case TLSDomain:
		if o.Domain == "" {
			return nil, fmt.Errorf("для TLS на домене нужен --domain")
		}
		cfg.sni = o.Domain
		if o.CertFile != "" && o.KeyFile != "" {
			dstCert := filepath.Join(tlsDir, "fullchain.pem")
			dstKey := filepath.Join(tlsDir, "key.pem")
			if err := copyFile(o.CertFile, dstCert, 0o644); err != nil {
				return nil, err
			}
			if err := copyFile(o.KeyFile, dstKey, 0o600); err != nil {
				return nil, err
			}
			cfg.certFile, cfg.keyFile = dstCert, dstKey
			info, err := certs.Describe(dstCert)
			if err != nil {
				return nil, err
			}
			if info.Pin != "" {
				cfg.pin = info.Pin
			}
			// Свои файлы тоже бывают самоподписанными: это видно по самому
			// сертификату, и клиенту тогда нужен allowInsecure.
			cfg.selfIssued = info.SelfIssued
			r.rep.Steps = append(r.rep.Steps, Step{Name: "TLS: свои файлы",
				Detail: fmt.Sprintf("%s / %s, до %s", dstCert, dstKey, info.NotAfter.Format("2006-01-02"))})
			return cfg, nil
		}
		if o.ACME == "off" {
			return nil, fmt.Errorf("нужны --cert/--key или --acme=http|dns")
		}
		if err := r.acme(o); err != nil {
			return nil, err
		}
		cfg.certFile = filepath.Join(tlsDir, "fullchain.pem")
		cfg.keyFile = filepath.Join(tlsDir, "key.pem")
		info, err := certs.Describe(cfg.certFile)
		if err != nil {
			r.rep.Steps = append(r.rep.Steps, Step{Name: "TLS: ACME", Err: err.Error()})
			return nil, err
		}
		cfg.pin = info.Pin
		r.rep.Steps = append(r.rep.Steps, Step{Name: "TLS: Let's Encrypt",
			Detail: fmt.Sprintf("%s, до %s (обновление — cron acme.sh)", o.Domain, info.NotAfter.Format("2006-01-02"))})
		return cfg, nil
	}
	return nil, fmt.Errorf("неизвестный режим TLS %q", o.Mode)
}

// acmeScript ищет acme.sh: наш каталог /etc/revhub/acme, домашний каталог
// пользователя, /root и PATH. Пустая строка — не установлен.
func acmeScript(etcDir string) string {
	cands := []string{}
	if etcDir != "" {
		cands = append(cands, filepath.Join(etcDir, "acme", "acme.sh"))
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		cands = append(cands, filepath.Join(home, ".acme.sh", "acme.sh"))
	}
	cands = append(cands, "/root/.acme.sh/acme.sh", "/usr/local/bin/acme.sh", "/usr/bin/acme.sh")
	for _, p := range cands {
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Size() > 0 {
			return p
		}
	}
	if p, err := exec.LookPath("acme.sh"); err == nil {
		return p
	}
	return ""
}

// acmeURLs — откуда берём сам скрипт. get.acme.sh не используем: его лоадер
// качает acme.sh с raw.githubusercontent и при сбое печатает «Install error»,
// но завершается с кодом 0 — установка «проходила», а acme.sh не появлялся.
var acmeURLs = []string{
	"https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh",
	"https://cdn.jsdelivr.net/gh/acmesh-official/acme.sh@master/acme.sh",
	"https://gitee.com/neilpang/acme.sh/raw/master/acme.sh",
}

// validACME проверяет, что скачался именно скрипт acme.sh, а не заглушка,
// captive-portal или HTML-ошибка.
func validACME(path string) bool {
	st, err := os.Stat(path)
	if err != nil || st.IsDir() || st.Size() < 20000 {
		return false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	txt := string(b)
	return strings.HasPrefix(txt, "#!") &&
		strings.Contains(txt, "LE_WORKING_DIR") &&
		strings.Contains(txt, "acme.sh")
}

// ensureACME возвращает путь к acme.sh, скачивая его в <EtcDir>/acme при
// необходимости. Рядом кладём systemd-таймер продления: acme.sh ставит cron
// через свой installer, а нам нужен предсказуемый путь без cron.
func (r *runner) ensureACME(o Options) (string, error) {
	if sh := acmeScript(o.EtcDir); sh != "" {
		return sh, nil
	}
	dst := filepath.Join(o.EtcDir, "acme", "acme.sh")
	if r.dry {
		return dst, nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", err
	}
	var errs []string
	for _, u := range acmeURLs {
		tmp := dst + ".part"
		if err := runCmd("curl", "-fsSL", "--retry", "3", "--max-time", "120", "-o", tmp, u); err != nil {
			errs = append(errs, u+": "+err.Error())
			os.Remove(tmp)
			continue
		}
		if !validACME(tmp) {
			errs = append(errs, u+": скачался не acme.sh")
			os.Remove(tmp)
			continue
		}
		if err := os.Rename(tmp, dst); err != nil {
			return "", err
		}
		if err := os.Chmod(dst, 0o755); err != nil {
			return "", err
		}
		r.rep.Steps = append(r.rep.Steps, Step{Name: "  acme.sh", Detail: dst + " ← " + u})
		break
	}
	sh := acmeScript(o.EtcDir)
	if sh == "" {
		return "", fmt.Errorf("не смог скачать acme.sh (%s). "+
			"Либо поставь его вручную, либо выбери TLS «самоподписанный на IP» — он не требует ACME",
			strings.Join(errs, "; "))
	}
	if err := r.writeAcmeTimer(o, sh); err != nil {
		r.rep.Steps = append(r.rep.Steps, Step{Name: "  таймер продления", Err: err.Error()})
	}
	return sh, nil
}

// writeAcmeTimer кладёт юнит и таймер ежедневного продления. Cert-файлы
// обновляются самим acme.sh (reloadcmd запоминается при --install-cert).
func (r *runner) writeAcmeTimer(o Options, sh string) error {
	dir := filepath.Join(o.EtcDir, "acme")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	svc := fmt.Sprintf(`[Unit]
Description=revhub: продление сертификатов acme.sh

[Service]
Type=oneshot
Environment=LE_WORKING_DIR=%s
ExecStart=%s --cron
`, dir, sh)
	timer := `[Unit]
Description=revhub: ежедневная проверка продления сертификатов

[Timer]
OnCalendar=*-*-* 03:17:00
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
`
	for name, body := range map[string]string{
		"revhub-acme-renew.service": svc,
		"revhub-acme-renew.timer":   timer,
	} {
		src := filepath.Join(dir, name)
		if err := os.WriteFile(src, []byte(body), 0o644); err != nil {
			return err
		}
		if err := os.MkdirAll(o.UnitDir, 0o755); err != nil {
			return err
		}
		if err := r.run("install", "-m", "644", src, filepath.Join(o.UnitDir, name)); err != nil {
			return err
		}
	}
	if r.dry || o.UnitDir != "/etc/systemd/system" {
		return nil
	}
	if err := r.run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	return r.run("systemctl", "enable", "--now", "revhub-acme-renew.timer")
}

// acme выпускает сертификат через acme.sh — тот же путь, что у x-ui.
func (r *runner) acme(o Options) error {
	r.rep.Steps = append(r.rep.Steps, Step{Name: "ACME: acme.sh", Detail: "проверяю"})
	sh, err := r.ensureACME(o)
	if err != nil {
		return err
	}
	issue := []string{sh, "--issue", "-d", o.Domain, "--keylength", "ec-256", "--server", "letsencrypt"}
	switch o.ACME {
	case "http":
		issue = append(issue, "--standalone")
	case "dns":
		if o.ACMEDNS == "" {
			return fmt.Errorf("для --acme=dns нужен --acme-dns (например dns_cf) и переменные провайдера в окружении")
		}
		issue = append(issue, "--dns", o.ACMEDNS)
	default:
		return fmt.Errorf("--acme должен быть http или dns")
	}
	if o.Email != "" {
		// аккаунт мог быть создан раньше — ошибку регистрации не считаем fatal
		_ = r.run(sh, "--register-account", "-m", o.Email)
	}
	if err := r.run(issue[0], issue[1:]...); err != nil {
		return fmt.Errorf("выпуск сертификата не удался: %w", err)
	}
	return r.installCert(sh, o.Domain, filepath.Join(o.EtcDir, "tls"))
}

// installCert раскладывает выпущенный сертификат по путям панели.
//
// Два момента, на которых мы уже спотыкались (и которые 3x-ui решает так же):
//  1. acme.sh не создаёт каталог назначения — "touch: cannot touch ... No such file";
//  2. при падении --reloadcmd acme.sh возвращает ненулевой код, хотя файлы уже
//     скопированы (юнитов ещё нет на шаге TLS). Поэтому код возврата не
//     считаем приговором: проверяем, что файлы на месте и непустые.
func (r *runner) installCert(sh, domain, certDir string) error {
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		return fmt.Errorf("каталог для сертификата %s: %w", certDir, err)
	}
	certFile := filepath.Join(certDir, "fullchain.pem")
	keyFile := filepath.Join(certDir, "key.pem")
	err := r.run(sh, "--install-cert", "--force", "-d", domain, "--ecc",
		"--fullchain-file", certFile,
		"--key-file", keyFile,
		"--reloadcmd", "systemctl try-restart xray || true; systemctl try-restart revhub || true")
	if r.dry {
		return nil
	}
	if verr := r.checkCert(certFile, keyFile); verr != nil {
		if err != nil {
			return fmt.Errorf("%w; acme.sh: %v", verr, err)
		}
		return verr
	}
	// ключ читает только root, сертификат — все
	_ = os.Chmod(keyFile, 0o600)
	_ = os.Chmod(certFile, 0o644)
	if err != nil {
		r.rep.Steps = append(r.rep.Steps, Step{Name: "  reloadcmd",
			Detail: "acme.sh вернул ошибку, но сертификат на месте: " + err.Error()})
	}
	return nil
}

// checkCert убеждается, что acme.sh действительно положил файлы: иначе панель
// поднимется без TLS и молча упадёт при старте.
func (r *runner) checkCert(certFile, keyFile string) error {
	if r.dry {
		return nil
	}
	for _, f := range []string{certFile, keyFile} {
		if st, err := os.Stat(f); err != nil || st.Size() == 0 {
			return fmt.Errorf("acme.sh не создал %s — сертификат не выпущен (проверь доступность :80 снаружи)", f)
		}
	}
	return nil
}

// securityForMode переводит режим установки в значение security инбаунда:
// «ip» и «domain» — это один и тот же TLS, различается лишь источник сертификата.
func securityForMode(mode string) string {
	switch mode {
	case TLSDomain, TLSIP, TLSIPLE:
		return "tls"
	case TLSReality:
		return "reality"
	default:
		return "none"
	}
}

// acmeIP выпускает сертификат Let's Encrypt на голый IP: LE требует профиль
// shortlived и допускает только HTTP-01 или TLS-ALPN-01 (DNS-01 для IP нет).
func (r *runner) acmeIP(o Options, ip string) error {
	port, email := o.ACMEHTTPPort, o.Email
	if port == 0 {
		port = 80
	}
	if email == "" {
		email = "admin@" + ip
	}
	sh, err := r.ensureACME(o)
	if err != nil {
		return err
	}
	// HTTP-01 поднимает свой листенер: занятый порт = непонятная ошибка ACME
	if !r.dry && portBusy(port) {
		return fmt.Errorf("порт %d занят: для HTTP-01 он должен быть свободен (или укажи --acme-http-port)", port)
	}
	if err := r.run(sh, "--set-default-ca", "--server", "letsencrypt", "--force"); err != nil {
		return err
	}
	if email != "" {
		_ = r.run(sh, "--register-account", "-m", email)
	}
	if err := r.run(sh, "--issue", "-d", ip, "--standalone", "--httpport", strconv.Itoa(port),
		"--server", "letsencrypt", "--certificate-profile", "shortlived", "--days", "6"); err != nil {
		return fmt.Errorf("выпуск на %s: %w (порт %d должен быть доступен снаружи)", ip, err, port)
	}
	return r.installCert(sh, ip, filepath.Join(o.EtcDir, "tls", "ip"))
}

// ---------------------------------------------------------------- состояние

// describeState — что именно попало в state.json: при установке «только панель»
// инбаундов, клиентов и правил нет, и отчёт не должен делать вид, что они есть.
func describeState(st model.State) string {
	if len(st.Inbounds) == 0 && len(st.Clients) == 0 {
		return " (только панель: ни инбаундов, ни клиентов — добавь в UI)"
	}
	return fmt.Sprintf(" (узлов %d, инбаундов %d, клиентов %d)",
		len(st.Nodes), len(st.Inbounds), len(st.Clients))
}

func writeState(o Options, cfg *tlsCfg, rep *Report) (model.State, error) {
	hostPort := o.Host
	if hostPort == "" {
		hostPort = "127.0.0.1"
	}
	st := model.State{Version: model.StateVersion}
	// Панель ставится пустой: никаких инбаундов, клиентов и правил «на всякий
	// случай» — всё это добавляется в UI. Остаётся только карточка этого хоста.
	publicAddr := fmt.Sprintf("%s:%d", hostPort, o.Port)
	if o.PanelOnly {
		if _, port, err := net.SplitHostPort(o.PanelAddr); err == nil {
			publicAddr = fmt.Sprintf("%s:%s", hostPort, port)
		}
	}
	st.Nodes = []model.Node{{
		ID: "node-1", Name: "Этот узел", Role: "both",
		PublicAddr: publicAddr, Core: "xray",
	}}
	if !o.PanelOnly {
		in := model.Inbound{
			ID: "in-1", NodeID: "node-1", Tag: "vless-main", Name: "Клиенты",
			Kind: "vless", Listen: "0.0.0.0", Port: o.Port, Transport: "tcp",
			Security: securityForMode(o.Mode), Enabled: true,
		}
		switch o.Mode {
		case TLSReality:
			in.SNI, in.Dest = cfg.sni, cfg.dest
			in.PrivateKey, in.PublicKey, in.ShortID = cfg.privateKey, cfg.publicKey, cfg.shortID
			in.Flow = "xtls-rprx-vision"
		case TLSDomain, TLSIP, TLSIPLE:
			in.CertFile, in.KeyFile = cfg.certFile, cfg.keyFile
			in.SelfSigned = o.Mode == TLSIP || cfg.selfIssued
			in.SNI = cfg.sni
			in.Domain = o.Domain
			switch {
			case o.Mode == TLSIP:
				in.CertSource, in.IP = "selfsigned", hostOnly(o.Host)
			case o.Mode == TLSIPLE:
				in.CertSource, in.IP = "acmeip", hostOnly(o.Host)
			case o.CertFile != "":
				in.CertSource = "file"
			default:
				in.CertSource = "acme"
			}
			if o.Mode == TLSDomain {
				in.Flow = ""
			}
		case TLSNone:
			in.Flow = ""
		}
		st.Inbounds = []model.Inbound{in}

		cl := model.Client{
			ID: "cl-1", Email: "default@revhub", UUID: model.GenUUID(), Enabled: true,
			Inbounds: []string{"in-1"}, SubToken: model.GenToken(),
		}
		if o.Mode == TLSReality {
			cl.Flow = "xtls-rprx-vision"
		}
		st.Clients = []model.Client{cl}
		st.Routes = []model.Rule{
			{ID: "r-1", Name: "RU-домены напрямую", Enabled: true,
				Domain: []string{"geosite:category-ru"}, Outbound: model.TagDirect},
			{ID: "r-2", Name: "Всё остальное — direct", Enabled: true, Outbound: model.TagDirect},
		}
	}
	// пустые списки — не null: UI ждёт массивы
	if st.Inbounds == nil {
		st.Inbounds = []model.Inbound{}
	}
	if st.Tunnels == nil {
		st.Tunnels = []model.Tunnel{}
	}
	if st.Clients == nil {
		st.Clients = []model.Client{}
	}
	if st.Routes == nil {
		st.Routes = []model.Rule{}
	}
	st.Normalize()
	if err := st.Validate(); err != nil {
		return st, fmt.Errorf("состояние не прошло валидацию: %w", err)
	}

	statePath := filepath.Join(o.EtcDir, "state.json")
	if _, err := os.Stat(statePath); err == nil {
		rep.Steps = append(rep.Steps, Step{Name: "состояние", Skipped: true,
			Detail: statePath + " уже есть — не перетираю"})
	} else {
		b, _ := json.MarshalIndent(st, "", "  ")
		if err := os.WriteFile(statePath, append(b, '\n'), 0o600); err != nil {
			return st, err
		}
		rep.Steps = append(rep.Steps, Step{Name: "состояние",
			Detail: statePath + describeState(st)})
	}

	// админ панели
	if _, err := auth.Load(statePath); err == nil {
		rep.PasswordFile = "(пароль уже был задан ранее)"
		rep.Steps = append(rep.Steps, Step{Name: "админ панели", Skipped: true, Detail: "пароль уже задан"})
	} else {
		pw := randomPassword()
		if _, err := auth.Create(statePath, o.AdminUser, pw); err != nil {
			return st, err
		}
		pf := filepath.Join(o.EtcDir, "initial-password")
		if err := os.WriteFile(pf, []byte(pw+"\n"), 0o600); err != nil {
			return st, err
		}
		rep.PasswordFile = pf
		if o.PrintPass {
			rep.Password = pw
		}
		rep.Steps = append(rep.Steps, Step{Name: "админ панели",
			Detail: fmt.Sprintf("пользователь %s, пароль в %s (0600)", o.AdminUser, pf)})
	}
	return st, nil
}

// ---------------------------------------------------------------- юниты

func revhubUnit(o Options, xrayPath string) string {
	tls := ""
	if o.PanelTLS && o.Mode != TLSReality && o.Mode != TLSNone {
		tls = fmt.Sprintf(" --tls-cert %s --tls-key %s",
			filepath.Join(o.EtcDir, "tls", "fullchain.pem"),
			filepath.Join(o.EtcDir, "tls", "key.pem"))
		if o.Mode == TLSIP {
			tls = fmt.Sprintf(" --tls-cert %s --tls-key %s",
				filepath.Join(o.EtcDir, "tls", "server.crt"),
				filepath.Join(o.EtcDir, "tls", "server.key"))
		}
		if o.Mode == TLSIPLE {
			tls = fmt.Sprintf(" --tls-cert %s --tls-key %s",
				filepath.Join(o.EtcDir, "tls", "ip", "fullchain.pem"),
				filepath.Join(o.EtcDir, "tls", "ip", "key.pem"))
		}
	}
	return fmt.Sprintf(`[Unit]
Description=revhub — панель туннелей
Documentation=file://%[1]s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%[2]s serve --state %[3]s --out %[4]s --addr %[5]s%[6]s
Restart=on-failure
RestartSec=3
StateDirectory=revhub
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=%[3]s %[4]s

[Install]
WantedBy=multi-user.target
`, o.EtcDir, filepath.Join(o.Prefix, "bin", "revhub"), filepath.Join(o.EtcDir, "state.json"),
		filepath.Join(o.StateDir, "out"), o.PanelAddr, tls)
}

func xrayUnit(xrayPath string) string {
	return `[Unit]
Description=Xray (revhub)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=` + xrayPath + ` run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=2
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
`
}

// ---------------------------------------------------------------- мелочи

type runner struct {
	dry bool
	rep *Report
}

var errSkip = fmt.Errorf("пропущено")

func (r *runner) step(name string, fn func() (string, error)) {
	detail, err := fn()
	s := Step{Name: name, Detail: detail}
	if err == errSkip {
		s.Skipped = true
		err = nil
	}
	if err != nil {
		s.Err = err.Error()
	}
	r.rep.Steps = append(r.rep.Steps, s)
}

func (r *runner) run(name string, args ...string) error {
	if r.dry {
		return nil
	}
	return runCmd(name, args...)
}

func withDefaults(o Options) Options {
	d := Defaults()
	if o.Prefix == "" {
		o.Prefix = d.Prefix
	}
	if o.EtcDir == "" {
		o.EtcDir = d.EtcDir
	}
	if o.StateDir == "" {
		o.StateDir = d.StateDir
	}
	if o.PanelAddr == "" {
		o.PanelAddr = d.PanelAddr
	}
	if o.Mode == "" {
		o.Mode = d.Mode
	}
	if o.ACME == "" {
		o.ACME = d.ACME
	}
	if o.Port == 0 {
		o.Port = d.Port
	}
	if o.AdminUser == "" {
		o.AdminUser = d.AdminUser
	}
	if o.UnitDir == "" {
		o.UnitDir = d.UnitDir
	}
	return o
}

func panelURL(o Options) string {
	host, port, ok := strings.Cut(o.PanelAddr, ":")
	scheme := "http"
	if o.PanelTLS {
		scheme = "https"
	}
	if !ok {
		return scheme + "://" + o.PanelAddr
	}
	if host == "0.0.0.0" || host == "" {
		host = "127.0.0.1"
		if o.Host != "" {
			host = o.Host // панель смотрит наружу: показываем реальный адрес входа
		}
	}
	return scheme + "://" + host + ":" + port
}

func randomPassword() string {
	b := make([]byte, 15)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// writableAncestor — можно ли писать в путь (или в ближайшего существующего
// предка): так установку можно прогнать в песочницу без root.
func writableAncestor(p string) bool {
	for {
		if st, err := os.Stat(p); err == nil {
			if !st.IsDir() {
				p = filepath.Dir(p)
				continue
			}
			f, err := os.OpenFile(filepath.Join(p, ".revhub-write-test"), os.O_CREATE|os.O_WRONLY, 0o600)
			if err != nil {
				return false
			}
			name := f.Name()
			f.Close()
			os.Remove(name)
			return true
		}
		parent := filepath.Dir(p)
		if parent == p {
			return false
		}
		p = parent
	}
}

func hostOnly(s string) string {
	if i := strings.LastIndex(s, ":"); i > 0 && !strings.Contains(s[i+1:], ":") {
		return s[:i]
	}
	return s
}

// portBusy сообщает, слушает ли кто-то порт на этой машине.
func portBusy(port int) bool {
	out, err := exec.Command("ss", "-ltnu").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), fmt.Sprintf(":%d ", port)) ||
		strings.Contains(string(out), fmt.Sprintf(":%d\n", port))
}

func short(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:8] + "…" + s[len(s)-6:]
}

// downloadXray тянет официальный релиз под текущую архитектуру.
func downloadXray(dst string) error {
	arch := "64"
	switch runtime.GOARCH {
	case "arm64":
		arch = "arm64-v8a"
	case "arm":
		arch = "arm32-v7a"
	}
	url := "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-" + arch + ".zip"
	cl := &http.Client{Timeout: 3 * time.Minute}
	resp, err := cl.Get(url)
	if err != nil {
		return fmt.Errorf("скачивание ядра: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("скачивание ядра: HTTP %d", resp.StatusCode)
	}
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		if f.Name != "xray" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, rc); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	}
	return fmt.Errorf("в архиве нет бинаря xray")
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(dst, in, mode); err != nil {
		return err
	}
	return os.Chmod(dst, mode)
}

func samePath(a, b string) bool {
	ra, err1 := filepath.EvalSymlinks(a)
	rb, err2 := filepath.EvalSymlinks(b)
	return err1 == nil && err2 == nil && ra == rb
}
