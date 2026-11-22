package bootstrap

import (
	"strings"
	"testing"
	"time"

	"revhub/internal/pkgmgr"
	"revhub/internal/sshx"
)

// Короткая пауза на время теста: ждать по-настоящему нечего.
func fastRetry(t *testing.T) {
	t.Helper()
	old := pkgmgr.Delay
	pkgmgr.Delay = time.Millisecond
	t.Cleanup(func() { pkgmgr.Delay = old })
}

// apt на свежем VPS держит cloud-init: установка узла обязана дождаться и
// сообщить об этом, а не падать с exit status 100.
func TestInstallWaitsForAptLock(t *testing.T) {
	fastRetry(t)
	f := newFakeRunner()
	f.noWG = true
	f.aptLocked = 2

	var log []string
	plan := Plan{InstallWG: true, RemoteDir: "/opt/revhub"}
	res, err := RunWith(openFake(f), sshx.Target{}, plan, func(s string) { log = append(log, s) })
	if err != nil {
		t.Fatalf("установка не должна падать на занятом apt: %v", err)
	}
	waited := 0
	for _, s := range log {
		if strings.Contains(s, "занят другим процессом") {
			waited++
		}
	}
	if waited != 2 {
		t.Fatalf("ожидали два сообщения об ожидании, получили %d: %v", waited, log)
	}
	aptCalls := 0
	for _, c := range f.cmds {
		if strings.Contains(c, "install -y -qq") {
			aptCalls++
		}
	}
	if aptCalls != 3 {
		t.Fatalf("ожидали 3 попытки apt (2 занято + успех), получили %d", aptCalls)
	}
	// В отчёте по шагу должно быть видно, что мы ждали, а не висели молча.
	found := false
	for _, s := range res.Steps {
		if s.Name == "пакеты" && strings.Contains(s.Detail, "ждали освобождения apt 2") {
			found = true
		}
	}
	if !found {
		t.Fatalf("шаг «пакеты» не отметил ожидание: %+v", res.Steps)
	}
}

// Замок не отдают вовсе — тогда ошибка, но с понятным объяснением.
func TestInstallGivesUpWithHintWhenLockNeverReleased(t *testing.T) {
	fastRetry(t)
	f := newFakeRunner()
	f.noWG = true
	f.aptLocked = pkgmgr.Attempts + 5

	_, err := RunWith(openFake(f), sshx.Target{}, Plan{InstallWG: true}, func(string) {})
	if err == nil {
		t.Fatal("ожидали ошибку, когда apt занят всегда")
	}
	if !strings.Contains(err.Error(), "cloud-init") {
		t.Fatalf("в ошибке должен быть совет про cloud-init: %v", err)
	}
	aptCalls := 0
	for _, c := range f.cmds {
		if strings.Contains(c, "install -y -qq") {
			aptCalls++
		}
	}
	if aptCalls != pkgmgr.Attempts {
		t.Fatalf("ждали %d попыток apt, получили %d", pkgmgr.Attempts, aptCalls)
	}
}
