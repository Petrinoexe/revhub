package apply

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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

// Каталог артефактов создал установщик от root: сохранение не должно падать,
// конфиг применяется, но в предупреждениях есть, как починить права.
func TestApplyFallsBackWhenArtifactsDirIsNotWritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root обходит права каталога")
	}
	helper := writeHelper(t, "#!/bin/sh\nexit 0\n")
	svc, dir := newService(t, helper, model.Node{ID: "hub"})
	locked := filepath.Join(dir, "out", "hub")
	if err := os.MkdirAll(locked, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o750) })

	rep := svc.ApplyNow("save")
	if len(rep.Nodes) != 1 || !rep.Nodes[0].OK {
		t.Fatalf("применение не прошло: %+v", rep.Nodes)
	}
	if len(rep.Warnings) == 0 || !strings.Contains(rep.Warnings[0], "revhub repair") {
		t.Fatalf("нет предупреждения про права: %+v", rep.Warnings)
	}
}

// Ошибка рендера (например, битые ключи туннеля) — провал применения, а не
// «пропущено»: иначе UI её спрячет и всё выглядит зелёным.
func TestApplyRenderErrorIsFailureNotSkip(t *testing.T) {
	helper := writeHelper(t, "#!/bin/sh\nexit 0\n")
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	st, err := store.Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Replace(model.State{Version: model.StateVersion,
		Nodes: []model.Node{
			{ID: "hub", PublicAddr: "hub.example.com"},
			{ID: "exit", PublicAddr: "exit.example.com"},
		},
		Tunnels: []model.Tunnel{{ID: "t1", Name: "eu", Kind: model.TunnelWG, Enabled: true,
			FromNode: "hub", ToNode: "exit", Subnet: "10.77.1.0/30", ListenPort: 51900, Mark: 300,
			FromKeyPriv: "не-ключ", FromKeyPub: "не-ключ", ToKeyPriv: "не-ключ", ToKeyPub: "не-ключ"}}}); err != nil {
		t.Fatal(err)
	}
	svc := &Service{Store: st, OutDir: filepath.Join(dir, "out"), StatePath: statePath,
		LocalNode: "hub", Bin: helper, Method: "direct"}

	rep := svc.ApplyNow("save")
	if len(rep.Nodes) == 0 {
		t.Fatalf("ожидался хотя бы один узел: %+v", rep.Nodes)
	}
	res := rep.Nodes[0]
	if res.OK || res.Skipped {
		t.Fatalf("ошибка рендера должна быть провалом, а не пропуском: %+v", res)
	}
	if !strings.Contains(res.Err, "ключ") {
		t.Fatalf("причина не названа: %q", res.Err)
	}
}

func TestSaveDuringApplyRunsAgainWithLatestState(t *testing.T) {
	helper := writeHelper(t, "#!/bin/sh\nexit 0\n")
	svc, _ := newService(t, helper, model.Node{ID: "hub", Name: "Старое имя"})
	first := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	svc.Logf = func(string) {
		once.Do(func() {
			close(first)
			<-release
		})
	}

	svc.Start("manual")
	select {
	case <-first:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("первое применение не дошло до отчёта")
	}
	if err := svc.Store.Patch(func(st *model.State) error {
		st.Nodes[0].Name = "Новое имя"
		return nil
	}); err != nil {
		close(release)
		t.Fatal(err)
	}
	svc.Start("save")
	close(release)

	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		report := svc.Last()
		if !report.Running {
			if report.Reason != "save" || len(report.Nodes) != 1 || report.Nodes[0].Name != "Новое имя" || !report.Nodes[0].OK {
				t.Fatalf("последнее состояние не применилось: %+v", report)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("повторное применение не завершилось")
}
