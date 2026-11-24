package api

import (
	"net/http"
	"os/exec"
	"strings"

	"revhub/internal/gen"
	"revhub/internal/model"
)

// dnsStatus — вкладка DNS: зона из модели, записи, что именно уедет в
// dnsmasq и в каком состоянии сам сервис. Резолвер не наш: панель только
// рендерит конфиг, поэтому «живой» статус — это systemctl.
func (s *Server) dnsStatus(w http.ResponseWriter, r *http.Request) {
	st := s.Store.Snapshot()
	resp := map[string]any{
		"local_node": s.LocalNode,
		"zone":       "",
		"enabled":    false,
		"records":    []any{},
		"service":    dnsmasqState(),
	}
	if st.DNS != nil && st.DNS.Enabled() {
		conf, planned, err := gen.DNSMasq(st, s.LocalNode)
		resp["enabled"] = true
		resp["zone"] = st.DNS.Root
		resp["node_id"] = st.DNS.NodeID
		resp["port"] = st.DNS.Port
		resp["ttl"] = st.DNS.TTL
		resp["upstream"] = st.DNS.Upstream
		resp["panel"] = st.DNS.FQDN(DNSLabel(st))
		recs := model.DNSRecords(st, s.LocalNode)
		if recs == nil {
			recs = []model.DNSRecord{}
		}
		resp["records"] = recs
		resp["planned"] = planned && st.DNS.NodeID == s.LocalNode
		if planned && st.DNS.NodeID == s.LocalNode {
			// Показываем ровно то, что уедет на узел: конфиг и hosts.
			resp["conf"] = conf.Conf
			resp["hosts"] = conf.Hosts
			resp["path"] = gen.DNSMasqConfPath
		}
		if err != nil {
			resp["error"] = err.Error()
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, resp)
}

// dnsCheck — «что ответит резолвер на это имя»: ищем в зоне модели, без
// сети. Удобно, пока dnsmasq ещё не перезапущен.
func (s *Server) dnsCheck(w http.ResponseWriter, r *http.Request) {
	st := s.Store.Snapshot()
	name := model.NormalizeName(r.URL.Query().Get("name"))
	if name == "" || st.DNS == nil || !st.DNS.Enabled() {
		writeErr(w, http.StatusBadRequest, "нужно имя и включённая зона")
		return
	}
	// zone приходит из формы: если её только что поправили и не сохранили,
	// честнее сказать об этом, чем отвечать «имя не в зоне».
	editing := model.NormalizeName(r.URL.Query().Get("zone"))
	unsaved := editing != "" && editing != st.DNS.Root
	for _, rec := range model.DNSRecords(st, s.LocalNode) {
		if model.NormalizeName(rec.Name) == name {
			writeJSON(w, http.StatusOK, map[string]any{
				"found": true, "name": name, "ip": rec.IP, "kind": rec.Kind, "note": rec.Note,
				"unsaved_zone": unsaved,
			})
			return
		}
	}
	zone := st.DNS.Root
	hint := "имя не в зоне: ответит upstream"
	if editing != "" {
		zone = editing
	}
	if name == zone || strings.HasSuffix(name, "."+zone) {
		hint = "имени нет в зоне: dnsmasq ответит NXDOMAIN"
	}
	if unsaved {
		hint += " (зона в форме ещё не сохранена — сейчас в модели " + st.DNS.Root + ")"
	}
	writeJSON(w, http.StatusOK, map[string]any{"found": false, "name": name, "hint": hint})
}

// DNSLabel — метка панели в зоне (для UI и подписи).
func DNSLabel(st model.State) string {
	if st.DNS != nil && st.DNS.Panel != "" {
		return st.DNS.Panel
	}
	return model.DefaultDNSPanel
}

// dnsmasqState — «installed / active / enabled» без root: systemctl is-active
// доступен обычному пользователю и честно говорит, работает ли резолвер.
func dnsmasqState() map[string]any {
	out := map[string]any{"installed": false, "active": false, "enabled": false}
	if _, err := exec.LookPath("dnsmasq"); err == nil {
		out["installed"] = true
	}
	if out2, err := exec.Command("systemctl", "is-active", "dnsmasq").Output(); err == nil {
		out["active"] = strings.TrimSpace(string(out2)) == "active"
	}
	if en, err := exec.Command("systemctl", "is-enabled", "dnsmasq").Output(); err == nil {
		out["enabled"] = strings.TrimSpace(string(en)) == "enabled"
	}
	return out
}

// panelRestart перезапускает панель: адрес прослушивания живёт в состоянии,
// поэтому смена адреса = рестарт юнита. Ответ уходит до остановки процесса,
// сам рестарт ставится в очередь systemd (--no-block), иначе остановка юнита
// убила бы помощника вместе с ним.
func (s *Server) panelRestart(w http.ResponseWriter, r *http.Request) {
	if s.Bin == "" {
		writeErr(w, http.StatusServiceUnavailable,
			"перезапуск доступен только установленной панели (нет пути к бинарю)")
		return
	}
	st := s.Store.Snapshot()
	addr := st.Panel.Addr()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "restarting": true, "addr": addr,
		"hint": "панель перезапускается и слушает " + addr,
	})
	bin := s.Bin
	logf := s.Logf
	go func() {
		out, err := exec.Command("sudo", "-n", bin, "restart").CombinedOutput()
		if err != nil && logf != nil {
			logf("перезапуск панели: " + err.Error() + ": " + strings.TrimSpace(string(out)))
		}
	}()
}
