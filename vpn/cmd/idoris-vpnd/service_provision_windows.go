//go:build windows

package main

import "os"

// Windows installs do not use provisionSystemPaths. The stubs keep the
// package building. fileUID reports nothing, so an existing directory is not
// treated as owned by the installer.
func fileUID(os.FileInfo) (int, bool) { return 0, false }

func chmodDirNoFollow(path string, mode os.FileMode) error {
	return os.Chmod(path, mode) //nolint:gosec // G302: unused on the Windows install path
}
