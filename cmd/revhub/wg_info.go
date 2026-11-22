package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

// cmdWG — тонкая обёртка над `wg`, которая запускается от root через sudo из
// панели. Сам `wg show` требует CAP_NET_ADMIN, поэтому непривилегированная
// панель не может прочитать рукопожатия напрямую и получает «Operation not
// permitted» — а диагностика из-за этого врала «интерфейс не поднят».
//
//	revhub wg show <iface> latest-handshakes
//	revhub wg show interfaces
func cmdWG(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "revhub wg show interfaces | revhub wg show <iface> latest-handshakes")
		os.Exit(2)
	}
	bin := "wg"
	for _, c := range []string{"/usr/bin/wg", "/usr/sbin/wg", "/usr/local/bin/wg"} {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			bin = c
			break
		}
	}
	out, err := exec.Command(bin, args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if text != "" {
		fmt.Println(text)
	}
	if err != nil {
		log.Fatalf("wg %s: %v", strings.Join(args, " "), err)
	}
}
