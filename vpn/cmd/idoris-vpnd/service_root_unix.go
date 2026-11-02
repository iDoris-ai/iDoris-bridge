//go:build unix

package main

import (
	"errors"
	"os"
)

func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("service install --system must run as root; re-run with sudo")
	}
	return nil
}

func chownSystemRootImpl(path string) error {
	// Lchown does not follow a symlink that replaced the path after the
	// installer checked it. A real directory or regular file is unchanged.
	return os.Lchown(path, 0, 0) //nolint:gosec // G703: path is an install directory or the protected executable
}
