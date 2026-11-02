package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// installerUID is the account allowed to adopt an existing service directory.
// Tests replace it. Production is the installer's euid, which is root for
// service install --system.
var installerUID = os.Geteuid

// preflightSystemPaths rejects shared directories, symlinks, and directories
// the installer does not own. It does not create or chmod anything.
func preflightSystemPaths(root string, cfgJSON []byte) error {
	paths, err := systemReadWritePaths(cfgJSON)
	if err != nil {
		return err
	}
	for _, p := range paths {
		if err := rejectSharedRuntime(p); err != nil {
			return err
		}
		if err := rejectSharedProvisionTarget(p); err != nil {
			return err
		}
		if err := rejectProvisionTree(root, p); err != nil {
			return err
		}
	}
	return nil
}

func provisionDest(root, logical string) string {
	logical = path.Clean(logical)
	if root == "" {
		return logical
	}
	return filepath.Join(root, strings.TrimPrefix(logical, "/"))
}

// rejectProvisionTree walks the configured path under root with Lstat.
// A symlink is refused. A missing tail is allowed only when its parent is a
// real directory the installer owns and that directory is not world-writable.
// An existing service directory the installer owns is allowed so a reinstall
// can keep it. Host ancestors above root are not inspected: on macOS /var is
// a symlink, and tests pass a temp directory as root.
func rejectProvisionTree(root, logical string) error {
	logical = path.Clean(logical)
	rel := strings.TrimPrefix(logical, "/")
	if rel == "" || strings.Contains(rel, "..") {
		return fmt.Errorf("config: refusing to provision %s", logical)
	}
	parts := strings.Split(rel, "/")
	acc := root
	if acc == "" {
		acc = string(os.PathSeparator)
	}
	seen := 0
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		seen++
		next := filepath.Join(acc, part)
		fi, err := os.Lstat(next) //nolint:gosec // G703: next is one component of a ReadWritePaths directory
		if err != nil {
			if os.IsNotExist(err) {
				return rejectUntrustedParent(acc, logical)
			}
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("config: %s is a symlink; the system service will not follow it", next)
		}
		if !fi.IsDir() {
			return fmt.Errorf("config: %s is not a directory", next)
		}
		last := seen == len(parts)
		if last && !dirOwnedByInstaller(fi) {
			return fmt.Errorf("config: %s exists and is not owned by the installer; refusing to change it", next)
		}
		acc = next
	}
	return nil
}

func rejectUntrustedParent(parent, logical string) error {
	if parent == "" || parent == string(os.PathSeparator) {
		return nil
	}
	fi, err := os.Lstat(parent) //nolint:gosec // G703: parent is the directory that would contain a ReadWritePaths entry
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("config: %s is a symlink; the system service will not follow it", parent)
	}
	if !fi.IsDir() {
		return fmt.Errorf("config: %s is not a directory", parent)
	}
	if fi.Mode().Perm()&0o002 != 0 {
		return fmt.Errorf("config: %s is under a world-writable directory. The system service will not create it", logical)
	}
	if !dirOwnedByInstaller(fi) {
		return fmt.Errorf("config: %s is under a directory the installer does not own; refusing to change it", logical)
	}
	return nil
}

func dirOwnedByInstaller(fi os.FileInfo) bool {
	uid, ok := fileUID(fi)
	if !ok {
		return false
	}
	return uid == installerUID()
}

func applyProvisionDest(root, logical string) error {
	if err := rejectSharedProvisionTarget(logical); err != nil {
		return err
	}
	if err := rejectProvisionTree(root, logical); err != nil {
		return err
	}
	dest := provisionDest(root, logical)
	if err := mkdirProvision(dest); err != nil {
		return err
	}
	if err := rejectProvisionTree(root, logical); err != nil {
		return err
	}
	if err := chmodDirNoFollow(dest, 0o750); err != nil {
		return err
	}
	fi, err := os.Lstat(dest) //nolint:gosec // G703: dest is a ReadWritePaths directory from the operator config
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("config: %s is a symlink; the system service will not follow it", dest)
	}
	if !dirOwnedByInstaller(fi) {
		return fmt.Errorf("config: %s exists and is not owned by the installer; refusing to change it", dest)
	}
	return chownSystemRoot(dest)
}

// mkdirProvision creates dest and any missing parents without following a
// symlink. An existing real directory is left for the caller to chmod.
func mkdirProvision(dest string) error {
	dest = filepath.Clean(dest)
	fi, err := os.Lstat(dest) //nolint:gosec // G703: dest is a ReadWritePaths directory from the operator config
	if err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("config: %s is a symlink; the system service will not follow it", dest)
		}
		if !fi.IsDir() {
			return fmt.Errorf("config: %s is not a directory", dest)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	parent := filepath.Dir(dest)
	if parent != dest {
		if err := mkdirProvisionParents(parent); err != nil {
			return err
		}
	}
	if err := os.Mkdir(dest, 0o750); err != nil && !os.IsExist(err) { //nolint:gosec // G703: dest is a ReadWritePaths directory from the operator config
		return err
	}
	fi, err = os.Lstat(dest) //nolint:gosec // G703: dest is a ReadWritePaths directory from the operator config
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("config: %s is a symlink; the system service will not follow it", dest)
	}
	if !fi.IsDir() {
		return fmt.Errorf("config: %s is not a directory", dest)
	}
	return nil
}

func mkdirProvisionParents(dir string) error {
	dir = filepath.Clean(dir)
	if dir == "" || dir == "." || dir == string(filepath.Separator) {
		return nil
	}
	fi, err := os.Lstat(dir) //nolint:gosec // G703: dir is a parent of a ReadWritePaths directory
	if err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("config: %s is a symlink; the system service will not follow it", dir)
		}
		if !fi.IsDir() {
			return fmt.Errorf("config: %s is not a directory", dir)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	parent := filepath.Dir(dir)
	if parent != dir {
		if err := mkdirProvisionParents(parent); err != nil {
			return err
		}
	}
	if err := os.Mkdir(dir, 0o750); err != nil && !os.IsExist(err) { //nolint:gosec // G703: dir is a parent of a ReadWritePaths directory
		return err
	}
	fi, err = os.Lstat(dir) //nolint:gosec // G703: dir is a parent of a ReadWritePaths directory
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("config: %s is a symlink; the system service will not follow it", dir)
	}
	return nil
}
