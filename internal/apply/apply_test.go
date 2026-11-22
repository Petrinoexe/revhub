package apply

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"revhub/internal/model"
	"revhub/internal/store"
)

func newService(t *testing.T, helper string, nodes ...model.Node) (*Service, string) {
	t.Helper()
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	st, err := store.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Replace(model.State{Version: model.StateVersion, Nodes: nodes}); err != nil {
		t.Fatalf("состояние не прошло валидацию: %v", err)
	}
	svc := &Service{
		Store: st, OutDir: filepath.Join(dir, "out"), StatePath: statePath,
		LocalNode: nodes[0].ID, Bin: helper, Method: "direct",
	}
	return svc, dir
}

func writeHelper(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "helper.sh")
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestApplyRunsLocalHelperAndRendersArtifacts(t *testing.T) {
	helper := writeHelper(t, "#!/bin/sh\necho \"helper: $*\"\nexit 0\n")
	svc, dir := newService(t, helper, model.Node{ID: "hub", Name: "Хаб"})

	rep := svc.ApplyNow("save")
	if rep.Running {
		t.Fatal("отчёт должен быть завершён")
	}
	if len(rep.Nodes) != 1 {
		t.Fatalf("ожидался один узел, получено %d", len(rep.Nodes))
	}
	res := rep.Nodes[0]
	if !res.OK || !res.Local {
		t.Fatalf("локальный узел не применён: %+v", res)
	}
	if !strings.Contains(res.Output, "apply-local") || !strings.Contains(res.Output, "--node hub") {
		t.Fatalf("помощник вызван не так: %q", res.Output)
	}
	// Артефакты должны лежать на диске: их забирает удалённый узел и панель.
	if _, err := os.Stat(filepath.Join(dir, "out", "hub", "apply.sh")); err != nil {
		t.Fatalf("apply.sh не отрендерен: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "out", "hub", "manifest.json")); err != nil {
		t.Fatalf("manifest.json не записан: %v", err)
	}
}

func TestApplyReportsHelperFailure(t *testing.T) {
	helper := writeHelper(t, "#!/bin/sh\necho 'xray не запустился' >&2\nexit 1\n")
	svc, _ := newService(t, helper, model.Node{ID: "hub"})

	rep := svc.ApplyNow("save")
	if len(rep.Nodes) != 1 || rep.Nodes[0].OK {
		t.Fatalf("ошибка применения не видна: %+v", rep.Nodes)
	}
	if rep.Failed() != 1 {
		t.Fatalf("Failed() = %d, ожидалось 1", rep.Failed())
	}
	if !strings.Contains(rep.Nodes[0].Output, "xray не запустился") {
		t.Fatalf("вывод помощника потерян: %q", rep.Nodes[0].Output)
	}
	if _, err := svc.ApplyNode("hub"); err == nil {
		t.Fatal("ApplyNode должен вернуть ошибку")
	}
}

func TestApplySkipsRemoteWithoutSecret(t *testing.T) {
	helper := writeHelper(t, "#!/bin/sh\nexit 0\n")
	svc, dir := newService(t, helper, model.Node{ID: "hub"}, model.Node{ID: "exit", Name: "Выходной"})

	rep := svc.ApplyNow("save")
	if len(rep.Nodes) != 2 {
		t.Fatalf("ожидалось два узла, получено %d", len(rep.Nodes))
	}
	remote := rep.Nodes[1]
	if !remote.Skipped || !remote.OK {
		t.Fatalf("удалённый узел должен быть пропущен, а не провален: %+v", remote)
	}
	if len(rep.Warnings) == 0 {
		t.Fatal("пропуск удалённого узла обязан попасть в предупреждения")
	}
	// Артефакты для удалённого узла всё равно готовятся: их заберёт SSH-деплой.
	if _, err := os.Stat(filepath.Join(dir, "out", "exit", "apply.sh")); err != nil {
		t.Fatalf("артефакты удалённого узла не отрендерены: %v", err)
	}
}

func TestApplyOffLeavesNodeUntouched(t *testing.T) {
	svc, _ := newService(t, "/nonexistent", model.Node{ID: "hub"})
	svc.Method = "off"
	rep := svc.ApplyNow("save")
	if len(rep.Nodes) != 1 || !rep.Nodes[0].Skipped || !rep.Nodes[0].OK {
		t.Fatalf("при --apply=off узел должен быть пропущен: %+v", rep.Nodes)
	}
}

// Ошибка рендера (например, у инбаунда нет ни одного клиента) — провал
// применения, а не «пропущено»: иначе UI её спрячет и всё выглядит зелёным.
func TestApplyRenderErrorIsFailureNotSkip(t *testing.T) {
	helper := writeHelper(t, "#!/bin/sh\nexit 0\n")
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	st, err := store.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Replace(model.State{Version: model.StateVersion,
		Nodes: []model.Node{{ID: "hub"}},
		Inbounds: []model.Inbound{{ID: "in-1", NodeID: "hub", Tag: "vless", Kind: "vless",
			Port: 443, Transport: "tcp", Security: "none", Enabled: true}}}); err != nil {
		t.Fatal(err)
	}
	svc := &Service{Store: st, OutDir: filepath.Join(dir, "out"), StatePath: statePath,
		LocalNode: "hub", Bin: helper, Method: "direct"}

	rep := svc.ApplyNow("save")
	if len(rep.Nodes) != 1 {
		t.Fatalf("ожидался один узел: %+v", rep.Nodes)
	}
	res := rep.Nodes[0]
	if res.OK || res.Skipped {
		t.Fatalf("ошибка рендера должна быть провалом, а не пропуском: %+v", res)
	}
	if !strings.Contains(res.Err, "клиент") {
		t.Fatalf("причина не названа: %q", res.Err)
	}
}
