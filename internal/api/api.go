// Package api — HTTP-слой панели. Ничего не применяет на узле: только
// состояние, генерация ключей, рендер артефактов и dry-run маршрутов.
// Применение — руками через apply.sh из out/<node>/ (см. docs/ARCHITECTURE.md).
package api

import (
	"embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"revhub/internal/auth"
	"revhub/internal/gen"
	"revhub/internal/model"
	"revhub/internal/monitor"
	"revhub/internal/provision"
	"revhub/internal/route"
	"revhub/internal/secrets"
	"revhub/internal/store"
	"revhub/internal/sub"
)

//go:embed ui/index.html ui/login.html
var uiFS embed.FS

type Server struct {
	Store   *store.Store
	OutDir  string
	Auth    *auth.Credentials // nil только при --noauth
	Limiter *auth.Limiter
	NoAuth  bool
	Secrets *secrets.Store
	Prov    *provision.Service
	Mon     *monitor.Monitor
}

func (s *Server) Handler() http.Handler {
	if s.Limiter == nil {
		s.Limiter = auth.NewLimiter(8, 5*time.Minute)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/logout", s.logout)
	mux.HandleFunc("GET /api/me", s.me)
	mux.HandleFunc("GET /api/state", s.getState)
	mux.HandleFunc("PUT /api/state", s.putState)
	mux.HandleFunc("POST /api/gen", s.genKeys)
	mux.HandleFunc("GET /api/preview", s.preview)
	mux.HandleFunc("POST /api/render", s.render)
	mux.HandleFunc("GET /api/route-check", s.routeCheck)
	mux.HandleFunc("GET /api/sub-link", s.subLink)
	mux.HandleFunc("POST /api/node/secret", s.setSecret)
	mux.HandleFunc("POST /api/node/provision", s.provisionNode)
	mux.HandleFunc("POST /api/node/check", s.checkNodes)
	mux.HandleFunc("GET /sub/{token}", s.subscription)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /", s.index)
	return logRequests(s.authGate(mux))
}

// authGate пускает без пароля только вход, подписку и healthcheck.
// Подписка обязана быть публичной: клиент обновляет её по токену.
func (s *Server) authGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.NoAuth || s.publicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if c, err := r.Cookie(auth.CookieName); err == nil && s.Auth != nil &&
			s.Auth.ValidSession(c.Value, time.Now()) {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeErr(w, http.StatusUnauthorized, "нужен вход в панель")
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
}

func (s *Server) publicPath(p string) bool {
	switch {
	case p == "/login", p == "/api/login", p == "/healthz":
		return true
	case strings.HasPrefix(p, "/sub/"):
		return true
	}
	return false
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	b, err := uiFS.ReadFile("ui/login.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if s.Auth == nil {
		writeErr(w, http.StatusServiceUnavailable, "авторизация отключена (--noauth)")
		return
	}
	var req struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "не разобрал JSON")
		return
	}
	ip := clientIP(r)
	now := time.Now()
	if !s.Limiter.Allow(ip, now) {
		writeErr(w, http.StatusTooManyRequests,
			fmt.Sprintf("слишком много попыток, подождите %s", s.Limiter.Wait(ip, now)))
		return
	}
	if !s.Auth.Verify(req.User, req.Password) {
		s.Limiter.Fail(ip, now)
		writeErr(w, http.StatusUnauthorized, "неверный пользователь или пароль")
		return
	}
	s.Limiter.Reset(ip)
	http.SetCookie(w, &http.Cookie{
		Name:     auth.CookieName,
		Value:    s.Auth.NewSession(now),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
		MaxAge:   int(auth.SessionTTL.Seconds()),
	})
	writeJSON(w, http.StatusOK, map[string]any{"user": s.Auth.User})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: auth.CookieName, Value: "", Path: "/", HttpOnly: true, MaxAge: -1,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	if s.Auth == nil {
		writeJSON(w, http.StatusOK, map[string]any{"user": "", "noauth": true})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": s.Auth.User})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) getState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Store.Snapshot())
}

func (s *Server) putState(w http.ResponseWriter, r *http.Request) {
	var st model.State
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20))
	if err := dec.Decode(&st); err != nil {
		writeErr(w, http.StatusBadRequest, "не разобрал JSON: "+err.Error())
		return
	}
	if err := s.Store.Replace(st); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.Store.Snapshot())
}

func (s *Server) genKeys(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Query().Get("what") {
	case "wg":
		priv, pub, err := model.GenWGKeys()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"private": priv, "public": pub})
	case "reality":
		priv, pub, err := model.GenRealityKeys()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"private": priv, "public": pub,
			"short_id": model.GenShortID()})
	case "uuid":
		writeJSON(w, http.StatusOK, map[string]string{"uuid": model.GenUUID()})
	case "token":
		writeJSON(w, http.StatusOK, map[string]string{"token": model.GenToken()})
	default:
		writeErr(w, http.StatusBadRequest, "what=wg|reality|uuid|token")
	}
}

func (s *Server) preview(w http.ResponseWriter, r *http.Request) {
	st := s.Store.Snapshot()
	node := r.URL.Query().Get("node")
	b, err := gen.XrayJSON(st, node)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(b)
}

func (s *Server) render(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Node string `json:"node"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "не разобрал JSON: "+err.Error())
		return
	}
	st := s.Store.Snapshot()
	files, err := gen.Artifacts(st, req.Node)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	dir := filepath.Join(s.OutDir, req.Node)
	man, err := gen.WriteArtifacts(dir, files)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	man.Node = req.Node
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), man.JSON(), 0o640); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	type item struct {
		Name string `json:"name"`
		Size int    `json:"size"`
		SHA  string `json:"sha"`
	}
	var items []item
	for _, f := range files {
		items = append(items, item{Name: f.Name, Size: len(f.Content), SHA: man.Files[f.Name]})
	}
	writeJSON(w, http.StatusOK, map[string]any{"dir": dir, "files": items})
}

func (s *Server) routeCheck(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	d := route.Check(s.Store.Snapshot(), route.Query{
		Node: q.Get("node"), User: q.Get("user"), Inbound: q.Get("inbound"),
		Domain: q.Get("domain"), IP: q.Get("ip"), Port: q.Get("port"), Network: q.Get("network"),
	})
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) subLink(w http.ResponseWriter, r *http.Request) {
	st := s.Store.Snapshot()
	id := r.URL.Query().Get("client")
	for _, c := range st.Clients {
		if c.ID != id {
			continue
		}
		links := sub.Links(st, c)
		writeJSON(w, http.StatusOK, map[string]any{
			"url":   "/sub/" + c.SubToken,
			"count": len(links),
			"links": links,
			"b64":   sub.Payload(links),
		})
		return
	}
	writeErr(w, http.StatusNotFound, "клиент не найден")
}

func (s *Server) subscription(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	st := s.Store.Snapshot()
	for _, c := range st.Clients {
		if c.SubToken != token {
			continue
		}
		links := sub.Links(st, c)
		body := sub.Payload(links)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Profile-Title", c.Email)
		w.Header().Set("Subscription-Userinfo",
			fmt.Sprintf("upload=0; download=0; total=%d", int64(c.QuotaGB*1024*1024*1024)))
		_, _ = w.Write([]byte(body))
		return
	}
	http.Error(w, "not found", http.StatusNotFound)
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	b, err := uiFS.ReadFile("ui/index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

// setSecret принимает пароль или путь к ключу; содержимое ключа читается на
// панели, чтобы приватный ключ не гулял по сети в открытом JSON.
func (s *Server) setSecret(w http.ResponseWriter, r *http.Request) {
	if s.Secrets == nil {
		writeErr(w, http.StatusServiceUnavailable, "хранилище секретов не подключено")
		return
	}
	var req struct {
		NodeID   string `json:"node_id"`
		Password string `json:"password"`
		KeyFile  string `json:"key_file"`
		User     string `json:"user"`
		SSHAddr  string `json:"ssh_addr"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "не разобрал JSON")
		return
	}
	if req.NodeID == "" {
		writeErr(w, http.StatusBadRequest, "нужен node_id")
		return
	}
	sec := secrets.Secret{Password: req.Password}
	if req.KeyFile != "" {
		b, err := os.ReadFile(req.KeyFile)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "ключ: "+err.Error())
			return
		}
		sec.PrivateKey = string(b)
	}
	if sec.Password == "" && sec.PrivateKey == "" {
		writeErr(w, http.StatusBadRequest, "нужен пароль или ключ")
		return
	}
	if err := s.Secrets.Set(req.NodeID, sec); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// заодно обновляем ssh-параметры узла, если их передали
	if req.User != "" || req.SSHAddr != "" {
		_ = s.Store.Patch(func(st *model.State) error {
			for i := range st.Nodes {
				if st.Nodes[i].ID != req.NodeID {
					continue
				}
				if req.User != "" {
					st.Nodes[i].SSHUser = req.User
				}
				if req.SSHAddr != "" {
					st.Nodes[i].SSHAddr = req.SSHAddr
				}
				st.Nodes[i].SSHAuth = "password"
				if sec.PrivateKey != "" {
					st.Nodes[i].SSHAuth = "key"
				}
			}
			return nil
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// provisionNode — «добавить хост и всё поставить». Долгая операция (SSH,
// пакеты, скачивание ядра), поэтому ответ отдаётся по завершении с полным логом.
func (s *Server) provisionNode(w http.ResponseWriter, r *http.Request) {
	if s.Prov == nil {
		writeErr(w, http.StatusServiceUnavailable, "установщик не подключён")
		return
	}
	var req provision.Request
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "не разобрал JSON")
		return
	}
	rep, err := s.Prov.Run(req)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error(), "report": rep})
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// checkNodes выполняет проверку немедленно (кнопка «проверить»).
func (s *Server) checkNodes(w http.ResponseWriter, r *http.Request) {
	if s.Mon == nil {
		writeErr(w, http.StatusServiceUnavailable, "монитор не подключён")
		return
	}
	writeJSON(w, http.StatusOK, s.Mon.CheckNow())
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg, "lines": strings.Split(msg, "\n")})
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("%s %s\n", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
