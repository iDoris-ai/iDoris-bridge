package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNEW1PlantedCredentialIsNotOverwritten is the macOS stand-in for the
// Windows staging race. A preexisting file is held open. The installer must
// fail without truncating it. This does not prove Windows ACL semantics.
func TestNEW1PlantedCredentialIsNotOverwritten(t *testing.T) {
	secret := []byte("SECRET-XYZ")
	cases := []struct {
		key  string
		name string
	}{
		{key: "enroll_token_file", name: "enroll_token"},
		{key: "auth_key_file", name: "auth_key"},
		{key: "socks5_auth_file", name: "socks5.auth"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := t.TempDir()
			source := filepath.Join(src, "source-secret")
			if err := os.WriteFile(source, secret, 0o600); err != nil {
				t.Fatal(err)
			}
			dest := t.TempDir()
			plantedPath := filepath.Join(dest, tc.name)
			planted := []byte("PLANTED-NEW1-" + tc.name)
			if err := os.WriteFile(plantedPath, planted, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(plantedPath, 0o644); err != nil {
				t.Fatal(err)
			}
			held, err := os.Open(plantedPath)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = held.Close() })

			body, err := json.Marshal(map[string]string{tc.key: source})
			if err != nil {
				t.Fatal(err)
			}
			_, _, stageErr := stageWindowsConfig(append(body, '\n'), dest)
			if _, err := held.Seek(0, 0); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(held)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(planted) || strings.Contains(string(got), string(secret)) {
				t.Fatalf("held file is %q, stage err %v", got, stageErr)
			}
			if stageErr == nil {
				t.Fatal("preexisting staged credential was overwritten")
			}
			onDisk, err := os.ReadFile(plantedPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(onDisk) != string(planted) {
				t.Fatalf("on disk %q", onDisk)
			}
			assertMode(t, plantedPath, 0o644)
		})
	}
}

// TestNEW1NonEmptyStageAfterProtect stops after the empty-directory ACL step
// when another file appeared. A name the installer would not itself write
// still has to abort the install before the live tree changes.
func TestNEW1StagedConfigFileIsExclusive(t *testing.T) {
	t.Log("exclusive create is host filesystem behavior; it does not prove Windows ACL semantics")
	dir := t.TempDir()
	dest := filepath.Join(dir, "vpn.json")
	planted := []byte("PLANTED-NEW1-vpn.json")
	if err := os.WriteFile(dest, planted, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dest, 0o644); err != nil {
		t.Fatal(err)
	}
	held, err := os.Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = held.Close() })
	secret := []byte("{\"marker\":\"SECRET-XYZ\"}\n")
	if err := writeStagedInstallFile(dest, secret, 0o600); err == nil {
		t.Fatal("preexisting staged vpn.json was overwritten")
	}
	if _, err := held.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(held)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(planted) || strings.Contains(string(got), "SECRET-XYZ") {
		t.Fatalf("held config is %q", got)
	}
	assertMode(t, dest, 0o644)
}

func TestNEW1NonEmptyStageAfterProtect(t *testing.T) {
	t.Log("staging ACL is stubbed; this test does not prove Windows icacls or DACL behavior")
	root := t.TempDir()
	liveDir := filepath.Join(root, "ProgramData", "idoris")
	exeDir := filepath.Join(root, "Program Files", "iDoris")
	if err := os.MkdirAll(liveDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(exeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	liveExe := filepath.Join(exeDir, "idoris-vpnd.exe")
	if err := os.WriteFile(liveExe, []byte("old-exe-new1"), 0o755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "new-vpnd-new1.exe")
	if err := os.WriteFile(src, []byte("new-exe-new1"), 0o755); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(root, "new1-token")
	if err := os.WriteFile(token, []byte("SECRET-XYZ"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(root, "new1-cfg.json")
	body, err := json.Marshal(map[string]string{"auth_key_file": token})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	prevProtect := protectWindowsInstallFn
	prevChown := chownSystemRoot
	prevRun := runServiceCommand
	calls := 0
	protectWindowsInstallFn = func(dir, config, exeDir, exe string, creds []string) error {
		calls++
		if calls == 1 && config == "" && exe == "" && len(creds) == 0 {
			// The inherited ProgramData ACL window, represented here by a
			// file planted before protect returns. Not a Windows ACL proof.
			return os.WriteFile(filepath.Join(dir, "note.txt"), []byte("planted-note"), 0o644)
		}
		return nil
	}
	chownSystemRoot = func(string) error { return nil }
	runServiceCommand = func(string, ...string) ([]byte, error) {
		t.Fatal("live install command ran after a non-empty stage")
		return nil, nil
	}
	t.Cleanup(func() {
		protectWindowsInstallFn = prevProtect
		chownSystemRoot = prevChown
		runServiceCommand = prevRun
	})

	spec := windowsReplaceSpec{
		SrcExe:     src,
		LiveExe:    liveExe,
		ExeDir:     exeDir,
		ConfigSrc:  cfgPath,
		LiveDir:    liveDir,
		LiveConfig: filepath.Join(liveDir, "vpn.json"),
		StagingDir: filepath.Join(root, "ProgramData", "idoris-install-new1-empty"),
		Active:     false,
	}
	err = replaceWindowsTask(spec)
	if err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("replace err %v", err)
	}
	if calls != 1 {
		t.Fatalf("protect calls %d, want 1", calls)
	}
	got, err := os.ReadFile(liveExe)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old-exe-new1" {
		t.Fatalf("live exe changed: %q", got)
	}
}
