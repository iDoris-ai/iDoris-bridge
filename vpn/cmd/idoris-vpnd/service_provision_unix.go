//go:build unix

package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func fileUID(fi os.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, false
	}
	return int(st.Uid), true
}

// chmodDirNoFollow changes the directory itself. O_NOFOLLOW fails with ELOOP
// when the last component is a symlink, so a planted link is not chmod'd.
func chmodDirNoFollow(path string, mode os.FileMode) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return fmt.Errorf("config: %s is a symlink; the system service will not follow it", path)
		}
		return err
	}
	if err := syscall.Fchmod(fd, uint32(mode)); err != nil { //nolint:gosec // G302: service directory mode is 0750
		_ = syscall.Close(fd)
		return err
	}
	return syscall.Close(fd)
}
