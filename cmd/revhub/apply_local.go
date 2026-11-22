package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"revhub/internal/gen"
	"revhub/internal/store"
)

// cmdApplyLocal применяет конфигурацию узла на этой машине. Вызывается панелью
// через `sudo -n <bin> apply-local`, поэтому:
//   - работает только от root;
//   - заново рендерит артефакты из state.json в приватный каталог root, а не
//     исполняет apply.sh из каталога панели (там файлы пишет непривилегированный
//     пользователь — исполнять их от root нельзя);
//   - печатает вывод применённого скрипта в stdout, чтобы панель показала его
//     пользователю.
func cmdApplyLocal(args []string) {
	fs := flag.NewFlagSet("apply-local", flag.ExitOnError)
	statePath := fs.String("state", "/etc/revhub/state.json", "файл состояния")
	node := fs.String("node", "node-1", "id локального узла")
	_ = fs.Parse(args)

	if os.Geteuid() != 0 {
		log.Fatalf("apply-local требует root (uid=%d); вызывается через sudo из панели", os.Geteuid())
	}
	st, err := store.Open(*statePath)
	if err != nil {
		log.Fatalf("состояние: %v", err)
	}
	files, err := gen.Artifacts(st.Snapshot(), *node)
	if err != nil {
		log.Fatalf("артефакты узла %s: %v", *node, err)
	}
	// Приватный каталог: 0700 и mktemp, чтобы чужой процесс не подменил скрипт
	// между записью и запуском.
	dir, err := os.MkdirTemp("", "revhub-apply-*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o700); err != nil {
		log.Fatal(err)
	}
	for _, f := range files {
		if err := os.WriteFile(dir+"/"+f.Name, []byte(f.Content), f.Mode); err != nil {
			log.Fatalf("запись %s: %v", f.Name, err)
		}
	}
	cmd := exec.Command("bash", "apply.sh")
	cmd.Dir = dir
	// sudo чистит PATH (secure_path), а ядро у нас в /usr/local/bin: без этого
	// apply.sh падал бы на `xray -test: command not found`.
	xrayBin := os.Getenv("XRAY_BIN")
	if xrayBin == "" {
		xrayBin = "xray"
		for _, c := range []string{"/usr/local/bin/xray", "/usr/bin/xray", "/opt/xray/xray"} {
			if st, err := os.Stat(c); err == nil && !st.IsDir() {
				xrayBin = c
				break
			}
		}
	}
	pathEnv := os.Getenv("PATH")
	dirs := []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}
	if pathEnv != "" {
		dirs = append(strings.Split(pathEnv, ":"), dirs...)
	}
	cmd.Env = append(os.Environ(), "PATH="+joinUnique(dirs), "XRAY_BIN="+xrayBin)
	out, runErr := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if text != "" {
		fmt.Println(text)
	}
	if runErr != nil {
		log.Fatalf("применение не удалось: %v", runErr)
	}
}

func joinUnique(dirs []string) string {
	seen := map[string]bool{}
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return strings.Join(out, ":")
}
