// Package mgmt — какой адрес использовать для управления узлом.
//
// Правило пользователя: если есть WG-туннель до узла, ходим по нему; напрямую —
// только когда туннеля нет или он умер. Это не только экономия внешнего трафика:
// SSH через туннель переживает смену публичного IP у выходного.
package mgmt

import (
	"bytes"
	"net"
	"strings"
	"time"

	"revhub/internal/model"
)

// Addrs возвращает адреса-кандидаты в порядке предпочтения (host:port).
func Addrs(st model.State, node model.Node) []string {
	var out []string
	for _, t := range st.Tunnels {
		if !t.Enabled || t.ToNode != node.ID {
			continue
		}
		if t.Kind != model.TunnelWG && t.Kind != model.TunnelWGReverse {
			continue
		}
		// адрес той стороны туннеля, где живёт узел (to = .2)
		toAddr, err := tunnelAddr(t.Subnet, true)
		if err != nil {
			continue
		}
		out = append(out, net.JoinHostPort(toAddr, sshPort(node.SSHAddr)))
	}
	if node.SSHAddr != "" {
		out = append(out, node.SSHAddr)
	} else if node.PublicAddr != "" {
		out = append(out, net.JoinHostPort(hostOnly(node.PublicAddr), "22"))
	}
	return dedupe(out)
}

// TunnelAddrFor отдаёт адрес конца туннеля на стороне узла (для отчётов).
func TunnelAddrFor(t model.Tunnel, toSide bool) string {
	a, err := tunnelAddr(t.Subnet, toSide)
	if err != nil {
		return ""
	}
	return a
}

// Probe проверяет, что на адресе действительно SSH: TCP-коннект сам по себе
// врёт (транспарентный прокси и перехватчики отвечают SYN-ACK на что угодно),
// поэтому ждём баннер SSH-2.0. Задержка считается до баннера.
func Probe(addr string, timeout time.Duration) (time.Duration, bool) {
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	start := time.Now()
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return 0, false
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil || n == 0 {
		return 0, false
	}
	if !bytes.HasPrefix(buf[:n], []byte("SSH-")) {
		return 0, false
	}
	return time.Since(start), true
}

func sshPort(sshAddr string) string {
	if _, port, err := net.SplitHostPort(sshAddr); err == nil && port != "" {
		return port
	}
	return "22"
}

func hostOnly(s string) string {
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return s
}

// tunnelAddr считает адрес конца туннеля из подсети /30: .1 — from, .2 — to.
func tunnelAddr(subnet string, toSide bool) (string, error) {
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", err
	}
	base := ipnet.IP.To4()
	if base == nil {
		return "", err
	}
	a := make(net.IP, 4)
	copy(a, base)
	if toSide {
		a[3] += 2
	} else {
		a[3]++
	}
	return a.String(), nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
