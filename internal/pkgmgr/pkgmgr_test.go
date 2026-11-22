package pkgmgr

import (
	"errors"
	"strings"
	"testing"
)

// Реальный текст apt, который мы увидели на свежем узле.
const lockText = `E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 1532 (apt-get)
E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), is another process using it?`

func TestBusyRecognisesLock(t *testing.T) {
	if !Busy(lockText) {
		t.Fatal("текст про занятый dpkg должен распознаваться")
	}
	// Обычная ошибка установки — это не гонка за блокировкой, её нельзя глотать.
	if Busy("E: Unable to locate package wireguard-tools") {
		t.Fatal("ошибку «нет пакета» нельзя путать с блокировкой")
	}
}

func TestCmdWaitsForLockItself(t *testing.T) {
	cmd := Cmd("wireguard-tools nftables")
	if !strings.Contains(cmd, "DPkg::Lock::Timeout=") {
		t.Fatalf("apt должен ждать блокировку сам: %s", cmd)
	}
	if !strings.Contains(cmd, "update -qq") || !strings.Contains(cmd, "install -y -qq wireguard-tools nftables") {
		t.Fatalf("команда должна обновлять индексы и ставить пакеты: %s", cmd)
	}
}

func TestExhaustedExplainsCause(t *testing.T) {
	err := Exhausted(errors.New("exit status 100"))
	if !strings.Contains(err.Error(), "cloud-init") {
		t.Fatalf("в ошибке нужен совет, кого ждать: %v", err)
	}
}
