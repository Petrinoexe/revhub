// Package monitor — постоянное наблюдение за узлами: живой ли, сколько задержка,
// когда был последний handshake WG и через что мы до него достаём.
package monitor

import (
	"context"
	"os/exec"
	"strings"
	"sync"
	"time"

	"revhub/internal/mgmt"
	"revhub/internal/model"
	"revhub/internal/store"
)

type Monitor struct {
	Store    *store.Store
	Interval time.Duration
	Timeout  time.Duration
	wgBin    string
	mu       sync.Mutex
}

type Status struct {
	NodeID    string `json:"node_id"`
	Status    string `json:"status"`
	Addr      string `json:"addr"`
	Via       string `json:"via"`
	Latency   int    `json:"latency_ms"`
	Handshake int    `json:"handshake_age"`
}

// Start запускает цикл проверок. Возвращается сразу; цикл живёт до отмены ctx.
func (m *Monitor) Start(ctx context.Context) {
	if m.Interval == 0 {
		m.Interval = 20 * time.Second
	}
	if m.Timeout == 0 {
		m.Timeout = 3 * time.Second
	}
	go func() {
		// Первую проверку делаем в горутине: пробинг узлов ждёт таймауты, и
		// панель не должна из-за этого задерживать старт HTTP-сервера.
		m.CheckNow()
		t := time.NewTicker(m.Interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.CheckNow()
			}
		}
	}()
}

// CheckNow проверяет все узлы и пишет статусы в состояние.
func (m *Monitor) CheckNow() []Status {
	st := m.Store.Snapshot()
	out := make([]Status, 0, len(st.Nodes))
	for _, n := range st.Nodes {
		cands := mgmt.Addrs(st, n)
		res := Status{NodeID: n.ID, Status: "dead", Handshake: -1}
		for i, addr := range cands {
			lat, ok := mgmt.Probe(addr, m.Timeout)
			if !ok {
				continue
			}
			res.Status, res.Addr, res.Latency = "alive", addr, int(lat.Milliseconds())
			if i == 0 && len(cands) > 1 {
				res.Via = "tunnel"
			} else {
				res.Via = "direct"
			}
			break
		}
		res.Handshake = m.handshakeAge(st, n.ID)
		out = append(out, res)
	}
	_ = m.Store.Patch(func(s *model.State) error {
		now := time.Now().UTC().Format(time.RFC3339)
		for _, r := range out {
			for i := range s.Nodes {
				if s.Nodes[i].ID != r.NodeID {
					continue
				}
				s.Nodes[i].Status = r.Status
				s.Nodes[i].LatencyMS = r.Latency
				s.Nodes[i].HandshakeAge = r.Handshake
				s.Nodes[i].LastCheck = now
				if r.Via != "" {
					s.Nodes[i].MgmtVia = r.Via
				}
			}
		}
		return nil
	})
	return out
}

// handshakeAge читает `wg show <if> latest-handshakes` на этой машине и
// возвращает возраст самого свежего рукопожатия в секундах (-1 = нет данных).
func (m *Monitor) handshakeAge(st model.State, nodeID string) int {
	iface := ""
	for _, t := range st.Tunnels {
		if !t.Enabled || t.ToNode != nodeID {
			continue
		}
		if t.Kind == model.TunnelWG || t.Kind == model.TunnelWGReverse {
			iface = t.WGInterface()
			break
		}
	}
	if iface == "" {
		return -1
	}
	bin := m.wgBin
	if bin == "" {
		bin = "wg"
	}
	out, err := exec.Command(bin, "show", iface, "latest-handshakes").Output()
	if err != nil {
		return -1
	}
	newest := int64(0)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		var ts int64
		for _, c := range f[1] {
			if c < '0' || c > '9' {
				return -1
			}
			ts = ts*10 + int64(c-'0')
		}
		if ts > newest {
			newest = ts
		}
	}
	if newest == 0 {
		return -1 // ни одного рукопожатия
	}
	age := time.Now().Unix() - newest
	if age < 0 {
		return 0
	}
	return int(age)
}
