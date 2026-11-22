// Package apply — «сохранил = применилось». Панель не держит отдельной
// вкладки рендера: после сохранения состояния она рендерит артефакты и
// применяет их — локально через привилегированный помощник (sudo + собственный
// бинарь), на другие узлы по SSH.
//
// Привилегии: панель работает от непривилегированного пользователя, а ядру и
// wg-quick нужен root. Поэтому локальное применение идёт через
// `sudo -n <bin> apply-local`, а сам помощник заново рендерит артефакты от root
// из state.json. Скрипт из каталога панели root не исполняет: файлы в out/
// пишет непривилегированный пользователь, и исполнять их от root нельзя.
package apply

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"revhub/internal/gen"
	"revhub/internal/model"
	"revhub/internal/secrets"
	"revhub/internal/store"
)

// Remote — применение конфигурации на другом узле (SSH).
type Remote interface {
	Deploy(nodeID string) (string, error)
}

// Service применяет состояние на узлы. Одна операция за раз: параллельные
// применения к одному ядру бессмысленны и мешают друг другу.
type Service struct {
	Store     *store.Store
	Secrets   *secrets.Store
	OutDir    string
	StatePath string
	LocalNode string
	Bin       string // путь к бинарю revhub (для apply-local)
	Method    string // auto | sudo | direct | off
	Remote    Remote // nil — удалённые узлы только помечаются предупреждением
	Timeout   time.Duration
	Logf      func(string)

	mu   sync.Mutex
	busy bool
	last Report
}

// NodeResult — итог применения на одном узле.
type NodeResult struct {
	NodeID   string        `json:"node_id"`
	Name     string        `json:"name,omitempty"`
	Local    bool          `json:"local"`
	Skipped  bool          `json:"skipped,omitempty"`
	OK       bool          `json:"ok"`
	Output   string        `json:"output,omitempty"`
	Err      string        `json:"err,omitempty"`
	Duration time.Duration `json:"duration_ns"`
}

// Report — что произошло при последнем применении.
type Report struct {
	Running    bool         `json:"running"`
	Reason     string       `json:"reason"` // save | manual | node
	StartedAt  time.Time    `json:"started_at"`
	FinishedAt time.Time    `json:"finished_at"`
	Nodes      []NodeResult `json:"nodes"`
	Warnings   []string     `json:"warnings,omitempty"`
}

func (r Report) Failed() int {
	n := 0
	for _, res := range r.Nodes {
		if !res.OK && !res.Skipped {
			n++
		}
	}
	return n
}

// Last отдаёт копию последнего отчёта (его опрашивает UI).
func (s *Service) Last() Report {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.last
	out.Nodes = append([]NodeResult(nil), s.last.Nodes...)
	out.Warnings = append([]string(nil), s.last.Warnings...)
	return out
}

// Start запускает применение в фоне. Если уже идёт — возвращает текущее.
func (s *Service) Start(reason string) Report {
	s.mu.Lock()
	if s.busy {
		out := s.last
		s.mu.Unlock()
		return out
	}
	s.busy = true
	s.last = Report{Running: true, Reason: reason, StartedAt: time.Now().UTC()}
	s.mu.Unlock()

	go func() {
		s.run(reason)
		s.mu.Lock()
		s.busy = false
		s.last.Running = false
		s.last.FinishedAt = time.Now().UTC()
		s.mu.Unlock()
	}()
	return s.Last()
}

// ApplyNow — синхронное применение (кнопка «применить сейчас»).
func (s *Service) ApplyNow(reason string) Report {
	s.mu.Lock()
	if s.busy {
		out := s.last
		s.mu.Unlock()
		return out
	}
	s.busy = true
	s.last = Report{Running: true, Reason: reason, StartedAt: time.Now().UTC()}
	s.mu.Unlock()

	s.run(reason)

	s.mu.Lock()
	s.busy = false
	s.last.Running = false
	s.last.FinishedAt = time.Now().UTC()
	out := s.last
	s.mu.Unlock()
	return out
}

func (s *Service) run(reason string) {
	st := s.Store.Snapshot()
	for _, n := range st.Nodes {
		res := s.applyNode(st, n)
		s.append(res)
	}
}

// ApplyNode применяет один узел синхронно (кнопка ⚙ в карточке узла).
func (s *Service) ApplyNode(nodeID string) (NodeResult, error) {
	s.mu.Lock()
	if s.busy {
		s.mu.Unlock()
		return NodeResult{}, fmt.Errorf("уже идёт применение: дождись окончания и повтори")
	}
	s.busy = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.busy = false
		s.mu.Unlock()
	}()

	st := s.Store.Snapshot()
	var node model.Node
	for _, n := range st.Nodes {
		if n.ID == nodeID {
			node = n
		}
	}
	if node.ID == "" {
		return NodeResult{}, fmt.Errorf("узел %q не найден", nodeID)
	}
	res := s.applyNode(st, node)
	if res.Err != "" {
		return res, fmt.Errorf("%s", res.Err)
	}
	return res, nil
}

func (s *Service) append(res NodeResult) {
	s.mu.Lock()
	s.last.Nodes = append(s.last.Nodes, res)
	s.mu.Unlock()
	if s.Logf != nil {
		s.Logf(fmt.Sprintf("apply %s: ok=%v err=%s", res.NodeID, res.OK, res.Err))
	}
}

func (s *Service) warn(msg string) {
	s.mu.Lock()
	s.last.Warnings = append(s.last.Warnings, msg)
	s.mu.Unlock()
}

// applyNode рендерит артефакты узла и применяет их: локальный узел — через
// привилегированный помощник, остальные — по SSH.
func (s *Service) applyNode(st model.State, n model.Node) NodeResult {
	started := time.Now()
	res := NodeResult{NodeID: n.ID, Name: n.Name, Local: n.ID == s.LocalNode}
	done := func(err error, output string) NodeResult {
		res.Duration = time.Since(started)
		res.Output = strings.TrimSpace(output)
		if err != nil {
			res.Err = err.Error()
			res.OK = false
			return res
		}
		res.OK = true
		return res
	}

	files, err := gen.Artifacts(st, n.ID)
	if err != nil {
		return done(err, "")
	}
	dir := filepath.Join(s.OutDir, n.ID)
	man, err := gen.WriteArtifacts(dir, files)
	if err != nil {
		return done(err, "")
	}
	man.Node = n.ID
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), man.JSON(), 0o640); err != nil {
		return done(err, "")
	}

	if res.Local {
		if s.effectiveMethod() == "off" {
			res.Skipped = true
			res.OK = true
			res.Output = "применение на панели выключено (--apply=off); артефакты в " + dir
			return done(nil, res.Output)
		}
		out, err := s.runHelper(n.ID)
		return done(err, out)
	}

	if s.Remote == nil {
		res.Skipped = true
		res.OK = true
		res.Output = "удалённое применение не настроено: артефакты в " + dir
		s.warn("узел " + label(n) + ": применение по SSH недоступно")
		return done(nil, res.Output)
	}
	if s.Secrets != nil {
		if sec, _ := s.Secrets.Get(n.ID); sec.Password == "" && sec.PrivateKey == "" {
			res.Skipped = true
			res.OK = true
			res.Output = "нет SSH-секрета для узла; артефакты в " + dir
			s.warn("узел " + label(n) + ": нет SSH-секрета, конфиг не применён")
			return done(nil, res.Output)
		}
	}
	out, err := s.Remote.Deploy(n.ID)
	return done(err, out)
}

func label(n model.Node) string {
	if n.Name != "" {
		return n.Name
	}
	return n.ID
}

func (s *Service) effectiveMethod() string {
	switch s.Method {
	case "", "auto":
		if os.Geteuid() == 0 {
			return "direct"
		}
		return "sudo"
	case "off", "direct", "sudo":
		return s.Method
	}
	return "sudo"
}

// runHelper вызывает `apply-local` — либо напрямую (панель уже root), либо
// через sudo без пароля. Правило sudoers ставит установщик.
func (s *Service) runHelper(nodeID string) (string, error) {
	bin := s.Bin
	if bin == "" {
		exe, err := os.Executable()
		if err != nil {
			return "", err
		}
		bin = exe
	}
	args := []string{"apply-local", "--node", nodeID}
	if s.StatePath != "" {
		args = append(args, "--state", s.StatePath)
	}
	name := bin
	if s.effectiveMethod() == "sudo" {
		name = "sudo"
		args = append([]string{"-n", bin}, args...)
	}
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	text := string(out)
	if ctx.Err() == context.DeadlineExceeded {
		return text, fmt.Errorf("применение не уложилось в %s", timeout)
	}
	if err != nil {
		if strings.Contains(text, "sudo:") || strings.Contains(text, "a password is required") {
			return text, fmt.Errorf("панель не может применить конфиг: нет правила sudo для %s apply-local", bin)
		}
		return text, err
	}
	return text, nil
}
