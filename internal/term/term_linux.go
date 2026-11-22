//go:build linux

// Package term — чтение пароля с терминала без эха.
// Своя реализация вместо golang.org/x/term, чтобы у панели не было внешних
// зависимостей (см. docs/DECISIONS.md, ADR-1).
package term

import (
	"syscall"
	"unsafe"
)

// IsTerminal сообщает, является ли fd терминалом.
func IsTerminal(fd int) bool {
	var t syscall.Termios
	_, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd),
		syscall.TCGETS, uintptr(unsafe.Pointer(&t)), 0, 0, 0)
	return errno == 0
}

// ReadPassword читает строку с выключенным эхом. Возвращает символы без \n.
func ReadPassword(fd int) ([]byte, error) {
	var old syscall.Termios
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd),
		syscall.TCGETS, uintptr(unsafe.Pointer(&old)), 0, 0, 0); errno != 0 {
		return nil, errno
	}
	noEcho := old
	noEcho.Lflag &^= syscall.ECHO
	noEcho.Lflag |= syscall.ICANON | syscall.ISIG
	noEcho.Iflag |= syscall.ICRNL
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd),
		syscall.TCSETS, uintptr(unsafe.Pointer(&noEcho)), 0, 0, 0); errno != 0 {
		return nil, errno
	}
	defer syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd),
		syscall.TCSETS, uintptr(unsafe.Pointer(&old)), 0, 0, 0)

	var buf [1]byte
	var out []byte
	for {
		n, err := syscall.Read(fd, buf[:])
		if n == 0 || err != nil {
			return out, err
		}
		switch buf[0] {
		case '\n', '\r':
			return out, nil
		case 0x7f, 0x08: // backspace
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, buf[0])
		}
	}
}
