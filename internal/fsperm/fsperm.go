// Package fsperm — права при атомарной замене файлов состояния.
//
// Панель работает непривилегированным пользователем, а пишут состояние и
// apply-local, и CLI из-под root. Если root создаст новый state.json с правами
// 0600 root:root и переименует его поверх, панель падает на старте:
// «open /etc/revhub/state.json: permission denied». Поэтому при замене файла
// права и владельца наследуем у прежнего файла (или у каталога, если файла ещё
// нет), а не берём «самые безопасные».
package fsperm

import (
	"os"
	"path/filepath"
	"syscall"
)

// Perm — что навесить на новый файл. UID/GID = -1 означает «не трогать».
type Perm struct {
	Mode os.FileMode
	UID  int
	GID  int
}

// Of считает права для замены path: у существующего файла — его собственные,
// у нового — владельца каталога. Каталог, доступный группе на запись (как
// /etc/revhub у панели), даёт 0660: иначе группа не прочитает состояние.
func Of(path string) Perm {
	if fi, err := os.Stat(path); err == nil {
		p := Perm{Mode: fi.Mode().Perm(), UID: -1, GID: -1}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			p.UID, p.GID = int(st.Uid), int(st.Gid)
		}
		return p
	}
	p := Perm{Mode: 0o600, UID: -1, GID: -1}
	fi, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return p
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		p.UID, p.GID = int(st.Uid), int(st.Gid)
		if fi.Mode().Perm()&0o020 != 0 { // каталог группе на запись
			p.Mode = 0o660
		}
	}
	return p
}

// Apply навешивает права на свежесозданный файл до rename. Не root менять
// владельца не может — тогда режим не расширяем: 0600 достаётся тому, кто пишет.
func (p Perm) Apply(file string) error {
	mode := p.Mode
	// Себе же chown не нужен и на некоторых системах запрещён; делаем только
	// когда владелец действительно другой.
	if p.UID >= 0 && (p.UID != os.Geteuid() || p.GID != os.Getegid()) {
		if err := os.Chown(file, p.UID, p.GID); err != nil {
			mode = 0o600 // не сможем отдать файл панели — не расширяем права
		}
	}
	return os.Chmod(file, mode)
}
