package api

import (
	"fmt"
	"net/http"

	"revhub/internal/gen"
	"revhub/internal/model"
)

// infraPeerConfig отдаёт wg-quick конфиг инфраструктурного пира: без него
// добавление пира в панели бессмысленно — машине нечего поднимать.
func (s *Server) infraPeerConfig(w http.ResponseWriter, r *http.Request) {
	st := s.Store.Snapshot()
	id := r.PathValue("peer")
	for _, p := range st.InfraPeers {
		if p.ID != id && p.Name != id {
			continue
		}
		conf, ok, err := gen.InfraPeerConfig(st, p)
		if err != nil {
			writeErr(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		if !ok {
			writeErr(w, http.StatusNotFound, "пир выключен или инфра-сеть не настроена")
			return
		}
		writeWGConfig(w, model.WireGuardConfigFilename(p.Name, p.ID), conf)
		return
	}
	http.Error(w, "пир не найден", http.StatusNotFound)
}

func writeWGConfig(w http.ResponseWriter, fileName, content string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fileName))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(content))
}
