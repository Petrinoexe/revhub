// Package pkgmgr — установка системных пакетов так, чтобы чужая блокировка
// apt/dpkg не валила установку узла.
//
// На свежем VPS индексы и пакеты обновляет cloud-init, на живой машине —
// unattended-upgrades. Оба держат /var/lib/dpkg/lock-frontend, и apt отвечает
// «Could not get lock». Это не ошибка конфигурации, а гонка за блокировкой:
// правильно подождать и сказать об этом, а не падать.
package pkgmgr

import (
	"fmt"
	"strings"
	"time"
)

// LockTimeout — сколько секунд apt ждёт блокировку сам (DPkg::Lock::Timeout).
const LockTimeout = 300

// Attempts — сколько раз повторяем, если apt всё равно ответил «занято»:
// старые версии apt параметр Lock::Timeout молча игнорируют.
const Attempts = 10

// Delay — пауза между попытками. Переменная, чтобы тесты не ждали по-настоящему.
var Delay = 15 * time.Second

// busyMarkers — признаки того, что блокировку держит другой процесс.
var busyMarkers = []string{
	"Could not get lock",
	"Could not open lock file",
	"Unable to acquire the dpkg frontend lock",
	"is another process using it",
	"dpkg frontend lock",
}

// Busy сообщает, что apt/dpkg занят чужим процессом (а не сломан).
func Busy(text string) bool {
	for _, m := range busyMarkers {
		if strings.Contains(text, m) {
			return true
		}
	}
	return false
}

// Cmd — команда установки пакетов для sh -c: обновить индексы и поставить.
// Lock::Timeout делает основную работу, внешний цикл повторов — страховка.
func Cmd(missing string) string {
	prefix := fmt.Sprintf("DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=%d ", LockTimeout)
	return prefix + "update -qq && " + prefix + "install -y -qq " + missing
}

// WaitMessage — что показать пользователю, пока ждём блокировку.
func WaitMessage(attempt int) string {
	return fmt.Sprintf("пакетный менеджер занят другим процессом (обычно cloud-init), ждём %s и пробуем снова — попытка %d из %d",
		Delay, attempt+1, Attempts)
}

// Exhausted — ошибка, когда блокировку так и не отдали.
func Exhausted(err error) error {
	return fmt.Errorf("%w (пакетный менеджер занят дольше %s: дождись завершения cloud-init/unattended-upgrades и повтори установку)",
		err, time.Duration(Attempts)*Delay)
}
