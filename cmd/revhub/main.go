// revhub — мини-панель для сети «хаб + выходные» с обратными туннелями.
//
//	revhub serve    [--addr 127.0.0.1:2096] [--state state.json] [--out out]
//	revhub render   --node <id> [--state state.json] [--out out]
//	revhub validate [--state state.json]
//	revhub demo     [--state demo-state.json]
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"revhub/internal/api"
	"revhub/internal/apply"
	"revhub/internal/auth"
	"revhub/internal/certs"
	"revhub/internal/gen"
	"revhub/internal/model"
	"revhub/internal/monitor"
	"revhub/internal/provision"
	"revhub/internal/secrets"
	"revhub/internal/store"
	"revhub/internal/term"
)

// version подставляется при сборке: -X main.version=<tag>.
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "serve":
		cmdServe(os.Args[2:])
	case "render":
		cmdRender(os.Args[2:])
	case "apply-local":
		cmdApplyLocal(os.Args[2:])
	case "repair":
		cmdRepair(os.Args[2:])
	case "wg":
		cmdWG(os.Args[2:])
	case "validate":
		cmdValidate(os.Args[2:])
	case "demo":
		cmdDemo(os.Args[2:])
	case "passwd":
		cmdPasswd(os.Args[2:])
	case "restart":
		cmdRestart(os.Args[2:])
	case "panel":
		cmdPanel(os.Args[2:])
	case "install":
		cmdInstall(os.Args[2:])
	case "tls":
		cmdTLS(os.Args[2:])
	case "version":
		fmt.Printf("revhub %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
	case "-h", "--help", "help":
		usage()
	default:
		usage()
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `revhub — панель для хаба с обратными туннелями

  revhub serve    [--addr 127.0.0.1:2096] [--state state.json] [--out out] [--noauth]
  revhub install  --host <ip|домен> [--tls domain|ip-le|ip|reality|none] [--domain d] [--panel-tls]
  revhub tls selfsigned --hosts ip[,домен] [--out DIR] [--days N]
  revhub tls info       --cert FILE [--json]
  revhub tls acme       --domain d --email e [--method http|dns] [--dns dns_cf]
  revhub passwd   [--state state.json] [--user admin] [--random --password-file f]
  revhub render   --node <id> [--state state.json] [--out out]
  revhub apply-local [--node <id>] [--state state.json]
  revhub repair   [--etc-dir /etc/revhub]   # юнит xray, sudo, применение конфига
  revhub wg       show interfaces | show <iface> latest-handshakes
  revhub restart  # перезапустить юнит панели (адрес берётся из состояния)
  revhub panel    [show|list]        # какой адрес слушает панель и какие есть
  revhub panel    set <адрес>       # localhost | wg[:<тег>] | <ip|host>[:порт]
  revhub panel    wg [<тег>]        # переключить на адрес WireGuard-интерфейса
  revhub panel    localhost         # только петля (доступ через ssh-туннель)
  revhub validate [--state state.json]
  revhub demo     [--state demo-state.json]
  revhub version
`)
	os.Exit(2)
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "", "адрес панели (по умолчанию — panel.listen из состояния)")
	statePath := fs.String("state", "state.json", "файл состояния")
	outDir := fs.String("out", "out", "каталог артефактов")
	noAuth := fs.Bool("noauth", false, "без пароля (только loopback, для отладки UI)")
	tlsCert := fs.String("tls-cert", "", "сертификат для HTTPS панели")
	tlsKey := fs.String("tls-key", "", "ключ для HTTPS панели")
	localNode := fs.String("local-node", "node-1", "id узла, на котором работает панель")
	applyMode := fs.String("apply", "auto", "применение конфига: auto | sudo | direct | off")
	fs.Parse(args)

	st, err := store.Open(*statePath)
	if err != nil {
		log.Fatal(err)
	}
	sec, err := secrets.Open(*statePath)
	if err != nil {
		log.Fatal(err)
	}
	// Адрес прослушивания живёт в состоянии: его меняют в панели и панель же
	// перезапускается. Флаг остался для ручного запуска и отладки.
	listen := st.Snapshot().Panel.Addr()
	if *addr != "" {
		listen = *addr
	}
	bin, _ := os.Executable()
	srv := &api.Server{Store: st, OutDir: *outDir, NoAuth: *noAuth, Secrets: sec,
		LocalNode: *localNode, TLSCert: *tlsCert, TLSKey: *tlsKey, Bin: bin, Logf: log.Printf}
	srv.Prov = &provision.Service{Store: st, Secrets: sec, OutDir: *outDir}
	srv.Apply = &apply.Service{
		Store: st, Secrets: sec, OutDir: *outDir, StatePath: *statePath,
		LocalNode: *localNode, Method: *applyMode, Remote: srv.Prov,
		Logf: func(s string) { log.Print(s) },
	}
	srv.Mon = &monitor.Monitor{Store: st}

	if *noAuth {
		host, _, _ := net.SplitHostPort(listen)
		if host != "127.0.0.1" && host != "localhost" && host != "::1" {
			log.Fatalf("--noauth допустим только на loopback, а не на %s", listen)
		}
		log.Printf("ВНИМАНИЕ: --noauth, панель без пароля на %s", listen)
	} else {
		cred, err := auth.Load(*statePath)
		if err != nil {
			log.Fatalf("%v", err)
		}
		srv.Auth = cred
	}
	httpSrv := &http.Server{
		Addr:              listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	scheme := "http"
	if *tlsCert != "" && *tlsKey != "" {
		scheme = "https"
	}
	srv.Mon.Start(context.Background()) // фоновый мониторинг узлов
	log.Printf("revhub: панель %s://%s, состояние %s, артефакты %s/, мониторинг каждые %s",
		scheme, listen, *statePath, *outDir, srv.Mon.Interval)
	if scheme == "https" {
		log.Fatal(serveWithRetry(httpSrv, true, *tlsCert, *tlsKey))
	}
	log.Fatal(serveWithRetry(httpSrv, false, "", ""))
}

// serveWithRetry ждёт появления адреса: в сети WireGuard панель стартует
// раньше, чем apply поднимет интерфейс, и bind падает с EADDRNOTAVAIL.
func serveWithRetry(srv *http.Server, useTLS bool, cert, key string) error {
	host, _, _ := net.SplitHostPort(srv.Addr)
	isLoop := host == "127.0.0.1" || host == "localhost" || host == "::1"
	for i := 1; ; i++ {
		var err error
		if useTLS {
			err = srv.ListenAndServeTLS(cert, key)
		} else {
			err = srv.ListenAndServe()
		}
		if err == nil || err == http.ErrServerClosed || isLoop {
			return err
		}
		if !errors.Is(err, syscall.EADDRNOTAVAIL) {
			return err
		}
		if i >= 40 {
			return fmt.Errorf("адрес %s так и не появился: %w", srv.Addr, err)
		}
		log.Printf("адрес %s ещё не готов (%v), повтор через 3 с", srv.Addr, err)
		time.Sleep(3 * time.Second)
	}
}

// cmdRestart перезапускает юнит панели. Вызывается панелью через sudo:
// адрес прослушивания берётся из состояния, поэтому смена адреса в UI — это
// рестарт. --no-block важен: systemd ставит job в очередь и останавливает
// юнит, не убивая сам вызов (иначе рестарт умер бы вместе с процессом).
func cmdRestart(args []string) {
	fs := flag.NewFlagSet("restart", flag.ExitOnError)
	unit := fs.String("unit", "revhub.service", "юнит панели")
	fs.Parse(args)
	out, err := exec.Command("systemctl", "--no-block", "restart", *unit).CombinedOutput()
	if err != nil {
		log.Fatalf("systemctl restart %s: %v: %s", *unit, err, strings.TrimSpace(string(out)))
	}
}

// cmdPasswd задаёт пароль панели: интерактивно (из stdin, с подтверждением)
// или генерирует случайный и пишет его в файл, чтобы значение не попало в
// переписку и историю команд.
func cmdPasswd(args []string) {
	fs := flag.NewFlagSet("passwd", flag.ExitOnError)
	statePath := fs.String("state", "state.json", "файл состояния (credentials.json кладётся рядом)")
	user := fs.String("user", "admin", "пользователь")
	random := fs.Bool("random", false, "сгенерировать случайный пароль")
	passFile := fs.String("password-file", "", "куда записать сгенерированный пароль (0600)")
	fs.Parse(args)

	var password string
	if *random {
		b := make([]byte, 18)
		if _, err := rand.Read(b); err != nil {
			log.Fatal(err)
		}
		password = base64.RawURLEncoding.EncodeToString(b)
	} else {
		fmt.Fprint(os.Stderr, "новый пароль: ")
		p1, err := readLine()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Fprint(os.Stderr, "повтори: ")
		p2, err := readLine()
		if err != nil {
			log.Fatal(err)
		}
		if p1 != p2 {
			log.Fatal("пароли не совпали")
		}
		password = p1
	}

	if _, err := auth.Create(*statePath, *user, password); err != nil {
		log.Fatal(err)
	}
	if *random {
		if *passFile == "" {
			log.Fatal("с --random нужен --password-file, чтобы не печатать пароль в терминал")
		}
		if err := os.WriteFile(*passFile, []byte(password+"\n"), 0o600); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("пароль записан в %s (права 0600), пользователь %s\n", *passFile, *user)
		return
	}
	fmt.Printf("пароль обновлён, пользователь %s\n", *user)
}

// readLine читает строку из stdin без эха в терминал.
func readLine() (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	r := bufio.NewReader(os.Stdin)
	s, err := r.ReadString('\n')
	return strings.TrimRight(s, "\r\n"), err
}

func cmdRender(args []string) {
	fs := flag.NewFlagSet("render", flag.ExitOnError)
	node := fs.String("node", "", "id узла")
	statePath := fs.String("state", "state.json", "файл состояния")
	outDir := fs.String("out", "out", "каталог артефактов")
	fs.Parse(args)
	if *node == "" {
		log.Fatal("нужен --node")
	}
	st, err := store.Open(*statePath)
	if err != nil {
		log.Fatal(err)
	}
	files, err := gen.Artifacts(st.Snapshot(), *node)
	if err != nil {
		log.Fatal(err)
	}
	dir := *outDir + "/" + *node
	man, err := gen.WriteArtifacts(dir, files)
	if err != nil {
		log.Fatal(err)
	}
	man.Node = *node
	if err := os.WriteFile(dir+"/manifest.json", man.JSON(), 0o640); err != nil {
		log.Fatal(err)
	}
	for _, f := range files {
		fmt.Printf("%-28s %6d B  %s\n", f.Name, len(f.Content), man.Files[f.Name][:12])
	}
	fmt.Printf("→ %s\n", dir)
}

func cmdValidate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	statePath := fs.String("state", "state.json", "файл состояния")
	fs.Parse(args)
	st, err := store.Open(*statePath)
	if err != nil {
		log.Fatal(err)
	}
	snap := st.Snapshot()
	if err := snap.Validate(); err != nil {
		log.Fatal(err)
	}
	for _, n := range snap.Nodes {
		if _, err := gen.XrayJSON(snap, n.ID); err != nil {
			log.Fatalf("узел %s: %v", n.ID, err)
		}
	}
	fmt.Printf("состояние валидно: %d узлов, %d инбаундов, %d туннелей, %d клиентов, %d правил\n",
		len(snap.Nodes), len(snap.Inbounds), len(snap.Tunnels), len(snap.Clients), len(snap.Routes))
}

func cmdDemo(args []string) {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	statePath := fs.String("state", "demo-state.json", "файл состояния")
	fs.Parse(args)
	if _, err := os.Stat(*statePath); err == nil {
		log.Fatalf("%s уже существует — не перетираю", *statePath)
	}
	st := model.Demo()
	// Демо показывает дефолтный путь: обычный TLS с самоподписанным
	// сертификатом на IP. Reality остаётся доступным в UI, но не по умолчанию.
	certDir, err := filepath.Abs("demo-certs")
	if err != nil {
		log.Fatal(err)
	}
	cr, err := certs.SelfSigned(certs.Options{Hosts: []string{"203.0.113.10"}, Prefix: filepath.Join(certDir, "server")})
	if err != nil {
		log.Fatal(err)
	}
	st.Inbounds[0].Security = "tls"
	st.Inbounds[0].SNI = "203.0.113.10"
	st.Inbounds[0].Dest = ""
	st.Inbounds[0].PrivateKey, st.Inbounds[0].PublicKey, st.Inbounds[0].ShortID = "", "", ""
	st.Inbounds[0].Flow = ""
	st.Inbounds[0].CertSource = "selfsigned"
	st.Inbounds[0].IP = "203.0.113.10"
	st.Inbounds[0].CertFile = cr.CertFile
	st.Inbounds[0].KeyFile = cr.KeyFile
	st.Inbounds[0].SelfSigned = true
	st.Nodes[0].PublicAddr = "203.0.113.10:443"
	if err := st.Validate(); err != nil {
		log.Fatalf("демо-состояние невалидно: %v", err)
	}
	b, _ := json.MarshalIndent(st, "", "  ")
	if err := os.WriteFile(*statePath, append(b, '\n'), 0o600); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("создано демо-состояние %s\n", *statePath)
}
