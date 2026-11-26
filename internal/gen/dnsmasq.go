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

// DNSMasq рендерит конфиг и зону для узла инфраструктуры. ok=false — DNS
// выключен, живёт на другом узле или инфраструктурная сеть не поднята.
func DNSMasq(st model.State, nodeID string) (DNSMasqFiles, bool, error) {
	if st.DNS == nil || !st.DNS.Enabled() || st.DNS.NodeID != nodeID {
		return DNSMasqFiles{}, false, nil
	}
	if st.Infra == nil || !st.Infra.Enabled || st.Infra.NodeID != nodeID {
		return DNSMasqFiles{}, false, nil
	}
	listen := st.Infra.ServerAddress()
	if listen == "" {
		return DNSMasqFiles{}, false, nil
	}
	if !validZone(st.DNS.Root) {
		return DNSMasqFiles{}, false, fmt.Errorf("DNS: зона %q не похожа на домен", st.DNS.Root)
	}

	var b strings.Builder
	b.WriteString("# revhub: DNS сети инфраструктуры (wg-infra) — генерируется панелью\n")
	b.WriteString("# клиентские DNS-запросы приходят сюда через Xray; правки перетираются\n")
	fmt.Fprintf(&b, "port=%d\n", st.DNS.Port)
	// Слушаем только адрес хаба в инфра-сети: наружу резолвер не торчит.
	fmt.Fprintf(&b, "listen-address=%s\n", listen)
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
	// Всё остальное — публичные резолверы через выбранный туннель. Источник
	// пакета — адрес конца туннеля, для него в PostUp есть ip rule в таблицу
	// метки; иначе dnsmasq ушёл бы напрямую с IP хаба.
	upstreams := st.DNS.Upstream
	if len(upstreams) == 0 {
		upstreams = []string{"1.1.1.1", "1.0.0.1"}
	}
	source := dnsTunnelSource(st, nodeID)
	b.WriteString("no-resolv\n")
	for _, up := range upstreams {
		addr, err := model.ResolverAddr(up)
		if err != nil {
			return DNSMasqFiles{}, false, err
		}
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return DNSMasqFiles{}, false, err
		}
		target := host
		if port != "53" {
			target = host + "#" + port
		}
		if source != "" {
			target += "@" + source
		}
		fmt.Fprintf(&b, "server=%s\n", target)
	}
	fmt.Fprintf(&b, "addn-hosts=%s\n", DNSHostsPath)

	var h strings.Builder
	h.WriteString("# revhub: зона DNS инфраструктуры — ip имя полное_имя\n")
	for _, rec := range model.DNSRecords(st, nodeID) {
		short := strings.SplitN(rec.Name, ".", 2)[0]
		fmt.Fprintf(&h, "%s	%s	%s\n", rec.IP, rec.Name, short)
	}
	return DNSMasqFiles{Conf: b.String(), Hosts: h.String()}, true, nil
}

// dnsTunnelSource — адрес конца туннеля, выбранного выходом клиентской сети
// (inbound.egress), иначе выходом самой инфра-сети. Пусто = выхода в туннель
// нет, dnsmasq спрашивает публичные DNS напрямую с IP хаба.
func dnsTunnelSource(st model.State, nodeID string) string {
	egress := ""
	tags := st.ValidTags(nodeID)
	for _, in := range st.Inbounds {
		if in.Enabled && in.NodeID == nodeID && strings.HasPrefix(in.Egress, model.TagTunnel) && tags[in.Egress] {
			egress = in.Egress
			break
		}
	}
	if egress == "" && st.Infra != nil && strings.HasPrefix(st.Infra.Egress, model.TagTunnel) && tags[st.Infra.Egress] {
		egress = st.Infra.Egress
	}
	name := strings.TrimPrefix(egress, model.TagTunnel)
	if name == "" {
		return ""
	}
	for _, t := range st.Tunnels {
		if !t.Enabled || t.Name != name || t.FromNode != nodeID {
			continue
		}
		from, _, err := t.Addrs()
		if err == nil {
			return from
		}
	}
	return ""
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
