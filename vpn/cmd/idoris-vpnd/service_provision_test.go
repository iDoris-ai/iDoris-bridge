package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPS1SharedProvisionTargetIsNotChanged is the PS-1 probe: the installer
// must not chmod or chown a shared directory that the service does not own,
// and it must not create the rest of the tree after that config is rejected.
func TestPS1SharedProvisionTargetIsNotChanged(t *testing.T) {
	cases := []struct {
		name string
		cfg  string
		rel  string
	}{
		{name: "tmp socket dir", cfg: `{"listen":"unix:/tmp/x.sock"}`, rel: "tmp"},
		{name: "etc state dir", cfg: `{"state_dir":"/etc"}`, rel: "etc"},
		{name: "srv state file parent", cfg: `{"state_file":"/srv/state.json"}`, rel: "srv"},
		{name: "home directory", cfg: `{"state_dir":"/home/alice"}`, rel: "home/alice"},
		{name: "var lib itself", cfg: `{"state_dir":"/var/lib"}`, rel: "var/lib"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			target := filepath.Join(root, tc.rel)
			if err := os.MkdirAll(target, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(target, 0o755); err != nil {
				t.Fatal(err)
			}
			control := filepath.Join(root, "ps1-control-"+strings.ReplaceAll(tc.name, " ", "-"))
			if err := os.Mkdir(control, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(control, 0o755); err != nil {
				t.Fatal(err)
			}
			prev := chownSystemRoot
			var owned []string
			chownSystemRoot = func(p string) error {
				owned = append(owned, p)
				return nil
			}
			t.Cleanup(func() { chownSystemRoot = prev })

			cfg := []byte(tc.cfg)
			if err := preflightSystemPaths(root, cfg); err == nil || !strings.Contains(err.Error(), "shared") {
				t.Fatalf("preflight err %v", err)
			}
			assertMode(t, target, 0o755)
			err := provisionSystemPaths(root, cfg)
			assertMode(t, target, 0o755)
			assertMode(t, control, 0o755)
			if err == nil || !strings.Contains(err.Error(), "shared") {
				t.Fatalf("provision err %v", err)
			}
			if _, err := systemReadWritePaths(cfg); err == nil || !strings.Contains(err.Error(), "shared") {
				t.Fatalf("systemReadWritePaths err %v", err)
			}
			if _, err := renderSystemdSystemUnit("/bin/idoris-vpnd", "/etc/idoris/vpn.json", cfg); err == nil {
				t.Fatal("unit rendered for a shared directory")
			}
			if containsPath(owned, target) {
				t.Fatalf("chowned shared target %s in %v", target, owned)
			}
			if _, err := os.Stat(filepath.Join(root, "var", "lib", "idoris")); err == nil {
				t.Fatal("rejected config still created /var/lib/idoris")
			}
		})
	}
}

// TestPS1SymlinkProvisionTargetIsNotFollowed plants a symlink where the
// installer would otherwise mkdir/chmod, plus a safe earlier directory whose
// mode must stay put when a later path is rejected.
func TestPS1SymlinkProvisionTargetIsNotFollowed(t *testing.T) {
	root := t.TempDir()
	victim := filepath.Join(root, "ps1-symlink-victim")
	if err := os.Mkdir(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	lib := filepath.Join(root, "var", "lib")
	if err := os.MkdirAll(lib, 0o755); err != nil {
		t.Fatal(err)
	}
	// A real service directory listed before the symlinked child. Rejecting
	// the child must not chmod this directory first.
	serviceDir := filepath.Join(lib, "idoris")
	if err := os.Mkdir(serviceDir, 0o710); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(serviceDir, 0o710); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(serviceDir, "node")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	parentLinkTarget := filepath.Join(root, "ps1-parent-link-victim")
	if err := os.Mkdir(parentLinkTarget, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parentLinkTarget, 0o755); err != nil {
		t.Fatal(err)
	}
	// Second root: an ancestor of the configured path is the symlink.
	root2 := t.TempDir()
	parentVictim := filepath.Join(root2, "ps1-ancestor-victim")
	if err := os.Mkdir(parentVictim, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parentVictim, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root2, "srv"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(parentVictim, filepath.Join(root2, "srv", "idoris")); err != nil {
		t.Fatal(err)
	}

	prev := chownSystemRoot
	chownSystemRoot = func(string) error { return nil }
	t.Cleanup(func() { chownSystemRoot = prev })

	cfg := []byte(`{"state_dir":"/var/lib/idoris/node"}`)
	err := preflightSystemPaths(root, cfg)
	assertMode(t, victim, 0o755)
	assertMode(t, serviceDir, 0o710)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("preflight symlink err %v", err)
	}
	err = provisionSystemPaths(root, cfg)
	assertMode(t, victim, 0o755)
	assertMode(t, serviceDir, 0o710)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("leaf symlink err %v", err)
	}
	if _, err := os.Stat(filepath.Join(victim, "node")); err == nil {
		t.Fatal("mkdir followed the leaf symlink")
	}

	err = provisionSystemPaths(root2, []byte(`{"state_file":"/srv/idoris/state.json"}`))
	assertMode(t, parentVictim, 0o755)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("ancestor symlink err %v", err)
	}
	entries, err := os.ReadDir(parentVictim)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("mkdir followed the ancestor symlink: %v", entries)
	}
}

// TestPS1ExistingServiceDirReinstall keeps a preexisting service-owned
// directory. Shared ancestors stay as they were.
func TestPS1ExistingServiceDirReinstall(t *testing.T) {
	root := t.TempDir()
	varLib := filepath.Join(root, "var", "lib")
	if err := os.MkdirAll(varLib, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(varLib, 0o755); err != nil {
		t.Fatal(err)
	}
	serviceDir := filepath.Join(varLib, "idoris")
	node := filepath.Join(serviceDir, "node")
	if err := os.MkdirAll(node, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(serviceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(node, 0o777); err != nil {
		t.Fatal(err)
	}
	untouched := filepath.Join(varLib, "ps1-untouched-sibling")
	if err := os.Mkdir(untouched, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(untouched, 0o755); err != nil {
		t.Fatal(err)
	}
	prev := chownSystemRoot
	var owned []string
	chownSystemRoot = func(p string) error {
		owned = append(owned, p)
		return nil
	}
	t.Cleanup(func() { chownSystemRoot = prev })

	cfg := []byte(`{"state_dir":"/var/lib/idoris/node","listen":"unix:/run/idoris/vpnd.sock"}`)
	if err := preflightSystemPaths(root, cfg); err != nil {
		t.Fatal(err)
	}
	assertMode(t, serviceDir, 0o700)
	assertMode(t, node, 0o777)
	assertMode(t, varLib, 0o755)
	if err := provisionSystemPaths(root, cfg); err != nil {
		t.Fatal(err)
	}
	assertMode(t, serviceDir, 0o750)
	assertMode(t, node, 0o750)
	assertMode(t, varLib, 0o755)
	assertMode(t, untouched, 0o755)
	if containsPath(owned, varLib) || containsPath(owned, untouched) {
		t.Fatalf("chowned a directory the service does not own: %v", owned)
	}
	if !containsPath(owned, serviceDir) || !containsPath(owned, node) {
		t.Fatalf("service dirs were not adopted: %v", owned)
	}
}

func TestPS1PathUnderSharedTmpIsRejected(t *testing.T) {
	root := t.TempDir()
	tmpDir := filepath.Join(root, "tmp")
	if err := os.Mkdir(tmpDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmpDir, 0o755); err != nil {
		t.Fatal(err)
	}
	prev := chownSystemRoot
	chownSystemRoot = func(string) error { return nil }
	t.Cleanup(func() { chownSystemRoot = prev })
	cfg := []byte(`{"state_dir":"/tmp/idoris-ps1"}`)
	err := provisionSystemPaths(root, cfg)
	if err == nil || !strings.Contains(err.Error(), "shared") {
		t.Fatalf("provision err %v", err)
	}
	assertMode(t, tmpDir, 0o755)
	if _, err := os.Lstat(filepath.Join(tmpDir, "idoris-ps1")); !os.IsNotExist(err) {
		t.Fatalf("created a directory under tmp: %v", err)
	}
}

func TestPS1WorldWritableParentIsNotUsed(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "custom-ps1")
	if err := os.Mkdir(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	prev := chownSystemRoot
	chownSystemRoot = func(string) error { return nil }
	t.Cleanup(func() { chownSystemRoot = prev })
	err := provisionSystemPaths(root, []byte(`{"state_dir":"/custom-ps1/idoris"}`))
	if err == nil || !strings.Contains(err.Error(), "world-writable") {
		t.Fatalf("provision err %v", err)
	}
	assertMode(t, parent, 0o777)
	if _, err := os.Lstat(filepath.Join(parent, "idoris")); !os.IsNotExist(err) {
		t.Fatalf("created a directory under a world-writable parent: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "var", "lib", "idoris")); !os.IsNotExist(err) {
		t.Fatalf("rejected config still created the service dir: %v", err)
	}
}

func TestPS1UnownedExistingDirIsNotChanged(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("uid 0 owns the temp directory, so it cannot stand in for another account")
	}
	root := t.TempDir()
	node := filepath.Join(root, "var", "lib", "idoris", "node")
	if err := os.MkdirAll(node, 0o700); err != nil {
		t.Fatal(err)
	}
	serviceDir := filepath.Dir(node)
	if err := os.Chmod(serviceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(node, 0o700); err != nil {
		t.Fatal(err)
	}
	prevUID := installerUID
	prevChown := chownSystemRoot
	installerUID = func() int { return 0 }
	chownSystemRoot = func(string) error { return nil }
	t.Cleanup(func() {
		installerUID = prevUID
		chownSystemRoot = prevChown
	})
	err := provisionSystemPaths(root, []byte(`{"state_dir":"/var/lib/idoris/node"}`))
	if err == nil || !strings.Contains(err.Error(), "not owned") {
		t.Fatalf("provision err %v", err)
	}
	assertMode(t, serviceDir, 0o700)
	assertMode(t, node, 0o700)
}

func assertMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != mode {
		t.Fatalf("%s mode %o, want %o", path, st.Mode().Perm(), mode)
	}
}
