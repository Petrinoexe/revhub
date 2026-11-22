package install

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// lookPath ищет бинарь в PATH.
func lookPath(bin string) (string, error) { return exec.LookPath(bin) }

// lookXray ищет ядро: сначала свой каталог, потом PATH.
func lookXray(prefix string) (string, error) {
	for _, p := range []string{filepath.Join(prefix, "bin", "xray"), "/usr/local/bin/xray"} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return exec.LookPath("xray")
}

// runCmd запускает команду и возвращает ошибку вместе с хвостом stderr —
// иначе на узле остаётся «install failed: exit status 1» без причины.
func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(out.String())
		if len(msg) > 800 {
			msg = msg[len(msg)-800:]
		}
		if msg == "" {
			return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
		}
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, msg)
	}
	return nil
}

// ACMECert — выпуск сертификата через acme.sh для подкоманды `revhub tls acme`.
func ACMECert(domain, email, method, provider, tlsDir string) error {
	if domain == "" {
		return fmt.Errorf("нужен домен")
	}
	r := &runner{rep: &Report{}}
	o := Options{Domain: domain, Email: email, ACME: method, ACMEDNS: provider, EtcDir: filepath.Dir(tlsDir)}
	return r.acme(o)
}
