package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"text/tabwriter"

	"revhub/internal/certs"
	"revhub/internal/install"
)

// cmdInstall — установка «как у x-ui»: бинарь, ядро, wireguard, сервис,
// админ, первый инбаунд и TLS в одном проходе.
func cmdInstall(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	o := install.Defaults()
	fs.StringVar(&o.Prefix, "prefix", o.Prefix, "куда ставить бинарь (/usr/local)")
	fs.StringVar(&o.EtcDir, "etc-dir", o.EtcDir, "конфиги и состояние")
	fs.StringVar(&o.StateDir, "state-dir", o.StateDir, "артефакты узла")
	fs.StringVar(&o.PanelAddr, "panel-addr", o.PanelAddr, "адрес панели")
	fs.BoolVar(&o.PanelTLS, "panel-tls", false, "панель по HTTPS (нужен сертификат: domain или ip)")
	fs.StringVar(&o.Host, "host", "", "публичный IP или домен узла")
	fs.StringVar(&o.Mode, "tls", o.Mode, "domain | ip-le | ip | reality | none")
	fs.StringVar(&o.Domain, "domain", "", "домен для TLS")
	fs.StringVar(&o.Email, "email", "", "email для ACME")
	fs.StringVar(&o.ACME, "acme", o.ACME, "http | dns | off")
	fs.StringVar(&o.ACMEDNS, "acme-dns", "", "провайдер DNS-01, напр. dns_cf")
	fs.StringVar(&o.CertFile, "cert", "", "готовый сертификат (вместо ACME)")
	fs.StringVar(&o.KeyFile, "key", "", "ключ к готовому сертификату")
	fs.IntVar(&o.Port, "port", o.Port, "порт VLESS")
	fs.IntVar(&o.ACMEHTTPPort, "acme-http-port", 80, "порт для HTTP-01 (нужен свободный и доступный извне)")
	fs.StringVar(&o.AdminUser, "user", o.AdminUser, "админ панели")
	fs.StringVar(&o.UnitDir, "unit-dir", o.UnitDir, "куда класть systemd-юниты")
	fs.BoolVar(&o.PanelOnly, "panel-only", o.PanelOnly, "не создавать инбаунд, клиента и правила (по умолчанию)")
	withInbound := fs.Bool("with-inbound", false, "создать стартовый VLESS-инбаунд и одного клиента")
	fs.BoolVar(&o.DryRun, "dry-run", false, "файлы писать, системные команды не выполнять")
	fs.BoolVar(&o.NoStart, "no-start", false, "не включать сервисы")
	fs.BoolVar(&o.NoApply, "no-apply", false, "не применять конфиг ядра")
	fs.BoolVar(&o.SkipPkgs, "skip-packages", false, "не ставить wireguard-tools/nftables")
	fs.BoolVar(&o.PrintPass, "print-password", false, "напечатать пароль (по умолчанию только путь к файлу)")
	asJSON := fs.Bool("json", false, "отдать отчёт в JSON")
	fs.Parse(args)
	if *withInbound {
		o.PanelOnly = false
	}

	rep, err := install.Run(o)
	if err != nil {
		printReport(rep, *asJSON)
		log.Fatalf("установка остановлена: %v", err)
	}
	printReport(rep, *asJSON)
}

func printReport(rep *install.Report, asJSON bool) {
	if asJSON {
		b, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(b))
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, s := range rep.Steps {
		mark := "✓"
		if s.Skipped {
			mark = "—"
		}
		if s.Err != "" {
			mark = "✗"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", mark, s.Name, s.Detail+s.Err)
	}
	w.Flush()

	fmt.Println()
	fmt.Println("панель:       ", rep.PanelURL)
	fmt.Println("пользователь: ", rep.AdminUser)
	fmt.Println("пароль:       ", rep.PasswordFile)
	if rep.Password != "" {
		fmt.Println("пароль (раз): ", rep.Password)
	}
	if rep.Pin != "" {
		fmt.Println("пин cert:     ", rep.Pin)
	}
	if rep.ClientLink != "" {
		fmt.Println("клиент:       ", rep.ClientLink)
	}
	if rep.SubURL != "" {
		fmt.Println("подписка:     ", rep.SubURL+" (относительно панели)")
	}
	if rep.ArtifactsDir != "" {
		fmt.Println("артефакты:    ", rep.ArtifactsDir)
	}
	fmt.Println()
	fmt.Println("дальше: systemctl status revhub; конфиг ядра применяется из",
		filepath.Join(rep.ArtifactsDir, "apply.sh"))
}

// cmdTLS — сертификаты отдельно от установки.
func cmdTLS(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "revhub tls selfsigned|info|acme")
		os.Exit(2)
	}
	switch args[0] {
	case "selfsigned":
		fs := flag.NewFlagSet("tls selfsigned", flag.ExitOnError)
		hosts := fs.String("hosts", "", "IP и/или домены через запятую")
		out := fs.String("out", "/etc/revhub/tls", "каталог")
		days := fs.Int("days", 3650, "срок, дней")
		name := fs.String("name", "server", "имя файлов без расширения")
		asJSON := fs.Bool("json", false, "JSON")
		fs.Parse(args[1:])
		if *hosts == "" {
			log.Fatal("нужен --hosts")
		}
		res, err := certs.SelfSigned(certs.Options{
			Hosts: splitList(*hosts), Days: *days, Prefix: filepath.Join(*out, *name),
		})
		if err != nil {
			log.Fatal(err)
		}
		if *asJSON {
			b, _ := json.MarshalIndent(res, "", "  ")
			fmt.Println(string(b))
			return
		}
		fmt.Printf("сертификат: %s\nключ:       %s\nSAN:        %v %v\nгоден до:   %s\nпин:        %s\n",
			res.CertFile, res.KeyFile, res.IPs, res.DNSNames,
			res.NotAfter.Format("2006-01-02"), res.Pin)
		fmt.Println("клиенту: allowInsecure=1 либо в xray-конфиге tlsSettings.pinnedPeerCertificateChainSha256 = [пин]")

	case "info":
		fs := flag.NewFlagSet("tls info", flag.ExitOnError)
		cert := fs.String("cert", "", "файл сертификата")
		asJSON := fs.Bool("json", false, "JSON")
		fs.Parse(args[1:])
		if *cert == "" {
			log.Fatal("нужен --cert")
		}
		info, err := certs.Describe(*cert)
		if err != nil {
			log.Fatal(err)
		}
		if *asJSON {
			b, _ := json.MarshalIndent(info, "", "  ")
			fmt.Println(string(b))
			return
		}
		fmt.Printf("файл:      %s\nдомены:    %v\nIP:        %v\nгоден до:  %s (%d дн.)\nсамоподп.: %v\nпин:       %s\n",
			info.CertFile, info.DNSNames, info.IPs, info.NotAfter.Format("2006-01-02"),
			info.DaysLeft, info.SelfIssued, info.Pin)

	case "acme":
		fs := flag.NewFlagSet("tls acme", flag.ExitOnError)
		domain := fs.String("domain", "", "домен")
		email := fs.String("email", "", "email для регистрации в LE")
		method := fs.String("method", "http", "http | dns")
		dns := fs.String("dns", "", "провайдер DNS-01 (dns_cf, dns_ovh, ...)")
		dir := fs.String("dir", "/etc/revhub/tls", "куда положить fullchain.pem/key.pem")
		fs.Parse(args[1:])
		if err := os.MkdirAll(*dir, 0o755); err != nil {
			log.Fatal(err)
		}
		if err := install.ACMECert(*domain, *email, *method, *dns, *dir); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("сертификат: %s/fullchain.pem\n", *dir)
		info, err := certs.Describe(filepath.Join(*dir, "fullchain.pem"))
		if err == nil {
			fmt.Printf("годен до %s, пин %s\n", info.NotAfter.Format("2006-01-02"), info.Pin)
		}

	default:
		fmt.Fprintln(os.Stderr, "revhub tls selfsigned|info|acme")
		os.Exit(2)
	}
}

func splitList(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == ',' || c == ' ' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(c)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
