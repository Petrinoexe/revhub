// Package bootstrap — первичная установка на удалённый узел по SSH.
//
// Ровно то, что делает `revhub install`, но по сети и без панели на той
// стороне: пакеты, ядро, юнит, артефакты узла, применение и проверка.
// Каждая ступень идемпотентна: повторный запуск не ломает уже настроенный узел.
package bootstrap

import (
	"fmt"
	"os"
	"strings"
	"time"

	"revhub/internal/gen"
	"revhub/internal/sshx"
)

// File — файл по абсолютному пути на узле (сертификаты и прочее).
type File struct {
	Path string
	Data []byte
	Mode os.FileMode
}

type Plan struct {
	Artifacts    []gen.File // готовые файлы узла: xray.json, wg-*.conf, apply.sh...
	Files        []File     // файлы по абсолютным путям (сертификаты)
	ACMEIP       string     // если задан — сертификат Let's Encrypt на голый IP (shortlived)
	ACMEHTTPPort int        // порт для HTTP-01 (по умолчанию 80)
	ACMEDomain   string     // если задан — выпустить сертификат на узле через acme.sh
	ACMEEmail    string
	ACMEDNS      string // пусто = HTTP-01 (нужен свободный :80)
	InstallXray  bool   // нужно ли ядро на этом узле
	InstallWG    bool   // есть ли WG-туннели
	XrayUnit     string // содержимое юнита, если ядро ставим мы
	RemoteDir    string // куда положить артефакты (по умолчанию /opt/revhub)
}

type Result struct {
	HostKey   string
	Log       []string
	XrayState string
	WGUp      []string
	EgressIP  string
	Duration  time.Duration
	Steps     []Step
}

type Step struct {
	Name   string
	Detail string
	Err    string
}

func (r *Result) Text() string {
	var b strings.Builder
	for _, s := range r.Steps {
		mark := "✓"
		if s.Err != "" {
			mark = "✗"
		}
		b.WriteString(mark + " " + s.Name + ": " + s.Detail + s.Err + "\n")
	}
	return b.String()
}

// Runner — то, что нужно установщику от узла. Интерфейс, а не *sshx.Client:
// так сценарий установки проверяется без SSH-сервера, а SSH-клиент остаётся
// единственным местом, где живёт протокол.
type Runner interface {
	Run(cmd string) (string, error)
	Upload(path string, data []byte, mode os.FileMode) error
	HostKey() string
}

// Open — как открыть соединение (по умолчанию SSH).
type Open func(t sshx.Target) (Runner, error)

// Run подключается и делает всё по плану. Возвращает результат даже при
// ошибке — по нему видно, на какой ступени остановились.
func Run(t sshx.Target, p Plan, logf func(string)) (*Result, error) {
	return RunWith(func(t sshx.Target) (Runner, error) { return sshx.Dial(t) }, t, p, logf)
}

// RunWith — то же с подменяемым транспортом (используется тестами).
func RunWith(open Open, t sshx.Target, p Plan, logf func(string)) (*Result, error) {
	res := &Result{}
	log := func(format string, a ...any) {
		line := fmt.Sprintf(format, a...)
		res.Log = append(res.Log, line)
		if logf != nil {
			logf(line)
		}
	}
	step := func(name string, fn func() (string, error)) error {
		s := Step{Name: name}
		detail, err := fn()
		s.Detail = detail
		if err != nil {
			s.Err = ": " + err.Error()
		}
		res.Steps = append(res.Steps, s)
		log("%s %s %s", name, detail, s.Err)
		return err
	}

	if p.RemoteDir == "" {
		p.RemoteDir = "/opt/revhub"
	}
	started := time.Now()
	cli, err := open(t)
	if err != nil {
		res.Steps = append(res.Steps, Step{Name: "ssh", Err: ": " + err.Error()})
		return res, err
	}
	if closer, ok := cli.(interface{ Close() error }); ok {
		defer closer.Close()
	}
	res.HostKey = cli.HostKey()

	if err := step("ssh", func() (string, error) {
		out, err := cli.Run("uid=$(id -u) || exit 1; printf '\\n__REVHUB_UID__=%s\\n' \"$uid\"")
		if err != nil {
			return "", fmt.Errorf("не удалось проверить UID по SSH: %w", err)
		}
		uid := ""
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "__REVHUB_UID__=") {
				if uid != "" {
					return "", fmt.Errorf("проверка UID: несколько результатов")
				}
				uid = strings.TrimPrefix(line, "__REVHUB_UID__=")
			}
		}
		if uid == "" {
			return "", fmt.Errorf("не удалось определить UID удалённого пользователя: id -u не вернул ожидаемый результат")
		}
		for _, c := range uid {
			if c < '0' || c > '9' {
				return "", fmt.Errorf("проверка UID: некорректный ответ %q", uid)
			}
		}
		if uid != "0" {
			return "", fmt.Errorf("нужен root на удалённом узле (uid=%s)", uid)
		}
		return "проверка root: uid=0", nil
	}); err != nil {
		return res, err
	}

	if p.InstallWG {
		if err := step("пакеты", func() (string, error) {
			missing := ""
			if _, err := cli.Run("command -v wg-quick"); err != nil {
				missing += "wireguard-tools "
			}
			if _, err := cli.Run("command -v nft || command -v iptables"); err != nil {
				missing += "nftables "
			}
			if missing == "" {
				return "уже стоят", nil
			}
			if _, err := cli.Run("DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq " + missing); err != nil {
				return "", err
			}
			return "поставлено: " + strings.TrimSpace(missing), nil
		}); err != nil {
			return res, err
		}
	}

	if p.InstallXray {
		if err := step("ядро xray", func() (string, error) {
			if out, err := cli.Run("command -v xray || test -x /usr/local/bin/xray && echo /usr/local/bin/xray"); err == nil {
				return "уже есть: " + strings.TrimSpace(out), nil
			}
			arch := "64"
			if out, err := cli.Run("uname -m"); err == nil {
				switch strings.TrimSpace(out) {
				case "aarch64", "arm64":
					arch = "arm64-v8a"
				case "armv7l":
					arch = "arm32-v7a"
				}
			}
			dl := fmt.Sprintf("https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-%s.zip", arch)
			cmd := fmt.Sprintf("curl -sSL -o /tmp/xray.zip %s && "+
				"(command -v unzip >/dev/null && unzip -o -q /tmp/xray.zip xray -d /tmp || "+
				"python3 -c \"import zipfile;zipfile.ZipFile('/tmp/xray.zip').extract('xray','/tmp')\") && "+
				"install -m 755 /tmp/xray /usr/local/bin/xray && rm -f /tmp/xray.zip /tmp/xray && "+
				"/usr/local/bin/xray version | head -1", dl)
			if _, err := cli.Run(cmd); err != nil {
				return "", fmt.Errorf("скачивание ядра: %w", err)
			}
			return "скачано " + arch, nil
		}); err != nil {
			return res, err
		}

		if p.XrayUnit != "" {
			if err := step("юнит xray", func() (string, error) {
				if _, err := cli.Run("test -f /etc/systemd/system/xray.service"); err == nil {
					return "уже есть", nil
				}
				if err := cli.Upload("/etc/systemd/system/xray.service", []byte(p.XrayUnit), 0o644); err != nil {
					return "", err
				}
				if _, err := cli.Run("systemctl daemon-reload"); err != nil {
					return "", err
				}
				return "создан и daemon-reload", nil
			}); err != nil {
				return res, err
			}
		}
	}

	if p.ACMEDomain != "" {
		if err := step("сертификат (ACME)", func() (string, error) {
			if _, err := cli.Run("test -s /etc/revhub/tls/fullchain.pem"); err == nil {
				return "уже выпущен", nil
			}
			if _, err := cli.Run("test -x /root/.acme.sh/acme.sh"); err != nil {
				if _, err := cli.Run("curl -sSL https://get.acme.sh | sh -s email=" + p.ACMEEmail); err != nil {
					return "", fmt.Errorf("acme.sh не установился: %w", err)
				}
			}
			issue := "/root/.acme.sh/acme.sh --issue -d " + p.ACMEDomain + " --keylength ec-256 --server letsencrypt"
			if p.ACMEDNS != "" {
				issue += " --dns " + p.ACMEDNS
			} else {
				issue += " --standalone"
			}
			if _, err := cli.Run(issue + `; rc=$?; [ "$rc" -eq 0 ] || [ "$rc" -eq 2 ]`); err != nil {
				return "", err
			}
			if _, err := cli.Run("mkdir -p /etc/revhub/tls"); err != nil {
				return "", fmt.Errorf("создание каталога сертификата: %w", err)
			}
			install := "/root/.acme.sh/acme.sh --install-cert -d " + p.ACMEDomain + " --ecc " +
				"--fullchain-file /etc/revhub/tls/fullchain.pem --key-file /etc/revhub/tls/key.pem " +
				"--reloadcmd 'systemctl restart xray || true'"
			if _, err := cli.Run(install); err != nil {
				return "", err
			}
			return "выпущен на " + p.ACMEDomain, nil
		}); err != nil {
			return res, err
		}
	}

	if p.ACMEIP != "" {
		if err := step("сертификат Let's Encrypt на IP", func() (string, error) {
			if _, err := cli.Run("test -s /etc/revhub/tls/ip/fullchain.pem"); err == nil {
				return "уже выпущен", nil
			}
			port := p.ACMEHTTPPort
			if port == 0 {
				port = 80
			}
			// порт 80 должен быть свободен: --standalone поднимает свой листенер
			if out, err := cli.Run(fmt.Sprintf("ss -ltnu 2>/dev/null | awk '{print $5}' | grep -c ':%d$' || true", port)); err == nil {
				if strings.TrimSpace(out) != "0" {
					return "", fmt.Errorf("порт %d занят: HTTP-01 требует свободный порт (освободи его или укажи другой через ACMEHTTPPort)", port)
				}
			}
			if _, err := cli.Run("test -x /root/.acme.sh/acme.sh"); err != nil {
				if _, err := cli.Run("curl -sSL https://get.acme.sh | sh -s email=" + p.ACMEEmail); err != nil {
					return "", fmt.Errorf("acme.sh не установился: %w", err)
				}
			}
			if _, err := cli.Run("/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt --force"); err != nil {
				return "", err
			}
			// --certificate-profile shortlived — требование LE для IP-сертификатов
			issue := fmt.Sprintf("/root/.acme.sh/acme.sh --issue -d %s --standalone --httpport %d "+
				"--server letsencrypt --certificate-profile shortlived --days 6 --force", p.ACMEIP, port)
			if _, err := cli.Run(issue + `; rc=$?; [ "$rc" -eq 0 ] || [ "$rc" -eq 2 ]`); err != nil {
				return "", fmt.Errorf("выпуск: %w (IP должен быть доступен снаружи по порту %d)", err, port)
			}
			if _, err := cli.Run("mkdir -p /etc/revhub/tls/ip"); err != nil {
				return "", fmt.Errorf("создание каталога сертификата: %w", err)
			}
			install := fmt.Sprintf("/root/.acme.sh/acme.sh --install-cert -d %s --ecc "+
				"--fullchain-file /etc/revhub/tls/ip/fullchain.pem --key-file /etc/revhub/tls/ip/key.pem "+
				"--reloadcmd 'systemctl restart xray || true'", p.ACMEIP)
			if _, err := cli.Run(install); err != nil {
				return "", err
			}
			return "выпущен на " + p.ACMEIP + " (shortlived, ~6 дней, продление — cron acme.sh)", nil
		}); err != nil {
			return res, err
		}
	}

	if len(p.Files) > 0 {
		if err := step("файлы узла", func() (string, error) {
			for _, f := range p.Files {
				if err := cli.Upload(f.Path, f.Data, f.Mode); err != nil {
					return "", fmt.Errorf("%s: %w", f.Path, err)
				}
			}
			return fmt.Sprintf("%d файлов", len(p.Files)), nil
		}); err != nil {
			return res, err
		}
	}

	if err := step("артефакты", func() (string, error) {
		var names []string
		for _, f := range p.Artifacts {
			path := p.RemoteDir + "/" + f.Name
			if err := cli.Upload(path, []byte(f.Content), f.Mode); err != nil {
				return "", fmt.Errorf("%s: %w", f.Name, err)
			}
			names = append(names, f.Name)
		}
		return fmt.Sprintf("%d файлов в %s", len(names), p.RemoteDir), nil
	}); err != nil {
		return res, err
	}

	if err := step("применение", func() (string, error) {
		out, err := cli.Run("cd " + p.RemoteDir + " && bash apply.sh")
		if err != nil {
			return strings.TrimSpace(out), err
		}
		return "apply.sh выполнен", nil
	}); err != nil {
		return res, err
	}

	if p.InstallXray {
		if err := step("проверка ядра", func() (string, error) {
			out, err := cli.Run("systemctl is-active xray")
			res.XrayState = strings.TrimSpace(out)
			if err != nil || res.XrayState != "active" {
				return "", fmt.Errorf("сервис xray не active (%s)", res.XrayState)
			}
			return res.XrayState, nil
		}); err != nil {
			return res, err
		}
	}

	if p.InstallWG {
		if err := step("проверка туннелей", func() (string, error) {
			out, err := cli.Run("wg show interfaces")
			if err != nil {
				return "", err
			}
			res.WGUp = strings.Fields(out)
			up := map[string]bool{}
			for _, name := range res.WGUp {
				up[name] = true
			}
			for _, file := range p.Artifacts {
				if strings.HasPrefix(file.Name, "wg-") && strings.HasSuffix(file.Name, ".conf") {
					name := strings.TrimSuffix(file.Name, ".conf")
					if !up[name] {
						return "", fmt.Errorf("интерфейс %s не поднялся", name)
					}
				}
			}
			return strings.Join(res.WGUp, ", "), nil
		}); err != nil {
			return res, err
		}
	}

	_ = step("выход в интернет", func() (string, error) {
		out, _ := cli.Run("curl -s -m 8 https://ifconfig.me/ip || true")
		res.EgressIP = strings.TrimSpace(out)
		if res.EgressIP == "" {
			return "", fmt.Errorf("IP не получен")
		}
		return res.EgressIP, nil
	})

	res.Duration = time.Since(started)
	return res, nil
}
