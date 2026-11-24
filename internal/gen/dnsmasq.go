package gen

import (
	"fmt"
	"net"
	"strings"

	"revhub/internal/model"
)

// DNSMasqFiles — артефакты резолвера клиентской сети: конфиг dnsmasq и файл
// hosts с зоной. Панель ничего не резолвит сама, она только рендерит эти два
// файла из модели, а dnsmasq (системный сервис) их читает.
type DNSMasqFiles struct {
	Conf  string // /etc/dnsmasq.d/revhub.conf
	Hosts string // /etc/revhub/dns-hosts
}

// DNSMasq рендерит конфиг и зону для узла. ok=false — DNS выключен или живёт
// на другом узле.
func DNSMasq(st model.State, nodeID string) (DNSMasqFiles, bool, error) {
	if st.DNS == nil || !st.DNS.Enabled() || st.DNS.NodeID != nodeID {
		return DNSMasqFiles{}, false, nil
	}
	var listens []string
	for _, in := range st.Inbounds {
		if !in.Enabled || in.NodeID != nodeID || in.Kind != model.InboundWireGuard || in.WireGuard == nil {
			continue
		}
		if addr := in.WireGuard.ServerAddress(); addr != "" {
			listens = append(listens, addr)
		}
	}
	if len(listens) == 0 {
		return DNSMasqFiles{}, false, fmt.Errorf("DNS: у узла %s нет включённого WireGuard-инбаунда", nodeID)
	}
	if !validZone(st.DNS.Root) {
		return DNSMasqFiles{}, false, fmt.Errorf("DNS: зона %q не похожа на домен", st.DNS.Root)
	}

	var b strings.Builder
	b.WriteString("# revhub: DNS клиентской сети WireGuard — генерируется панелью\n")
	b.WriteString("# правки на узле перетираются при следующем сохранении\n")
	fmt.Fprintf(&b, "port=%d\n", st.DNS.Port)
	// Только адреса WG-интерфейсов: наружу резолвер не торчит, а bind-dynamic
	// переживает момент, когда интерфейс ещё не поднят.
	for _, addr := range listens {
		fmt.Fprintf(&b, "listen-address=%s\n", addr)
	}
	b.WriteString("bind-dynamic\n")
	b.WriteString("# /etc/hosts машины не подмешиваем: зона — это модель панели\n")
	b.WriteString("no-hosts\n")
	b.WriteString("domain-needed\n")
	b.WriteString("bogus-priv\n")
	b.WriteString("cache-size=1000\n")
	fmt.Fprintf(&b, "domain=%s\n", st.DNS.Root)
	// local= делает зону авторитетной: имена, которых нет в hosts, получают
	// NXDOMAIN, а не уходят в интернет.
	fmt.Fprintf(&b, "local=/%s/\n", st.DNS.Root)
	if len(st.DNS.Upstream) > 0 {
		// Явные upstream'ы: /etc/resolv.conf узла не читаем, иначе резолвер
		// может спросить сам себя (системный 127.0.0.53).
		b.WriteString("no-resolv\n")
		for _, up := range st.DNS.Upstream {
			addr, err := model.ResolverAddr(up)
			if err != nil {
				return DNSMasqFiles{}, false, err
			}
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return DNSMasqFiles{}, false, err
			}
			if port == "53" {
				fmt.Fprintf(&b, "server=%s\n", host)
			} else {
				fmt.Fprintf(&b, "server=%s#%s\n", host, port)
			}
		}
	}
	fmt.Fprintf(&b, "addn-hosts=%s\n", DNSHostsPath)

	var h strings.Builder
	h.WriteString("# revhub: зона DNS клиентской сети — ip имя полное_имя\n")
	for _, rec := range model.DNSRecords(st, nodeID) {
		short := strings.SplitN(rec.Name, ".", 2)[0]
		fmt.Fprintf(&h, "%s\t%s\t%s\n", rec.IP, rec.Name, short)
	}
	return DNSMasqFiles{Conf: b.String(), Hosts: h.String()}, true, nil
}

// Пути на узле (их читает dnsmasq и пишет apply.sh).
const (
	DNSMasqConfPath  = "/etc/dnsmasq.d/revhub.conf"
	DNSHostsPath     = "/etc/revhub/dns-hosts"
	DNSMasqConfName  = "dnsmasq-revhub.conf"
	DNSHostsFileName = "dns-hosts"
)

// validZone — минимальная проверка домена для dnsmasq: метки через точку,
// буквы/цифры/дефис, не длиннее 253 символов.
func validZone(zone string) bool {
	if zone == "" || len(zone) > 253 {
		return false
	}
	for _, label := range strings.Split(zone, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i, r := range label {
			ok := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' && i > 0 && i < len(label)-1
			if !ok {
				return false
			}
		}
	}
	return true
}
