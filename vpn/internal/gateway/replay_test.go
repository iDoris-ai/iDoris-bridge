package gateway

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iDoris-ai/iDoris-bridge/vpn/internal/join"
)

const replayToken = "idv1_secretsecretsecretsecretsecretse"

func replayMemberPlan(t *testing.T, enroll, cfg, token string) Plan {
	t.Helper()
	p, err := SimplePlan(join.RoleMember, "acme", "laptop")
	if err != nil {
		t.Fatal(err)
	}
	p.EnrollURL = enroll
	p.ConfigPath = cfg
	p.TokenFile = token
	return p
}

type trackHost struct {
	*memHost
	stat  map[string]int
	read  map[string]int
	write map[string]int
}

func (h *trackHost) note(m *map[string]int, path string) {
	if *m == nil {
		*m = map[string]int{}
	}
	(*m)[filepath.Clean(path)]++
}

func (h *trackHost) Stat(path string) (os.FileInfo, error) {
	h.note(&h.stat, path)
	return h.memHost.Stat(path)
}

func (h *trackHost) ReadFile(path string) ([]byte, error) {
	h.note(&h.read, path)
	return h.memHost.ReadFile(path)
}

func (h *trackHost) WriteFile(path string, data []byte, mode os.FileMode) error {
	h.note(&h.write, path)
	return h.memHost.WriteFile(path, data, mode)
}

func TestPlanReplayKeepsGeneratedPlan(t *testing.T) {
	cfg := "/home/acme/.idoris/vpn.json"
	paths := PathsFor("", cfg)
	if paths.Plan != "/home/acme/.idoris/gateway-plan.json" || paths.Token != "/home/acme/.idoris/vpn.json.enroll-token" {
		t.Fatalf("paths %+v", paths)
	}
	p := replayMemberPlan(t, "https://enroll.good", cfg, paths.Token)
	h := newMemHost(false, "linux")
	if _, err := Apply(p, h, ApplyOptions{Token: replayToken, NoService: true, PlanPath: paths.Plan}); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPlan(bytes.NewReader(h.files[paths.Plan]))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.EnrollURL != "https://enroll.good" || loaded.TokenFile != paths.Token || loaded.ConfigPath != cfg {
		t.Fatalf("saved plan %+v", loaded)
	}
	if err := CheckPlanReplay(loaded, paths.Plan, h, false); err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), h.files[cfg]...)
	if _, err := Apply(loaded, h, ApplyOptions{Token: replayToken, NoService: true, PlanPath: paths.Plan, Replay: true}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, h.files[cfg]) {
		t.Fatalf("replay changed the config\n%s\n%s", before, h.files[cfg])
	}
	if string(h.files[paths.Token]) != replayToken+"\n" {
		t.Fatalf("token %q", h.files[paths.Token])
	}
}

func TestPlanReplayRejectsFreshConfigForeignToken(t *testing.T) {
	const (
		goodCfg = "/home/acme/.idoris/vpn.json"
		goodTok = "/home/acme/.idoris/enroll.token"
		evilCfg = "/home/acme/other/vpn.json"
	)
	base := newMemHost(false, "linux")
	base.files[goodCfg] = []byte("{\n  \"enroll_url\": \"https://enroll.good\",\n  \"enroll_token_file\": \"" + goodTok + "\"\n}\n")
	base.modes[goodCfg] = 0o600
	base.files[goodTok] = []byte(replayToken + "\n")
	base.modes[goodTok] = 0o600
	h := &trackHost{memHost: base}
	evilPlan := PathsFor("", evilCfg).Plan
	evil := replayMemberPlan(t, "https://evil.example", evilCfg, goodTok)
	beforeCfg := append([]byte(nil), base.files[goodCfg]...)
	beforeTok := append([]byte(nil), base.files[goodTok]...)
	for _, replace := range []bool{false, true} {
		err := CheckPlanReplay(evil, evilPlan, h, replace)
		if err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Fatalf("replace %v: %v", replace, err)
		}
		_, err = Apply(evil, h, ApplyOptions{Token: replayToken, PlanPath: evilPlan, Replay: true, ReplaceExisting: replace})
		if err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Fatalf("replace %v: %v", replace, err)
		}
	}
	if _, ok := base.files[evilCfg]; ok {
		t.Fatal("created the attacker config")
	}
	if !bytes.Equal(base.files[goodCfg], beforeCfg) || !bytes.Equal(base.files[goodTok], beforeTok) {
		t.Fatal("existing enrollment changed")
	}
	if h.stat[goodTok] != 0 || h.read[goodTok] != 0 || h.write[goodTok] != 0 {
		t.Fatalf("token was touched: stat %d read %d write %d", h.stat[goodTok], h.read[goodTok], h.write[goodTok])
	}
	if len(base.services) != 0 {
		t.Fatal("service installed")
	}
}

func TestPlanReplayRejectsCrossDirectoryToken(t *testing.T) {
	const (
		goodTok = "/home/acme/.idoris/enroll.token"
		evilCfg = "/home/acme/other/vpn.json"
	)
	base := newMemHost(false, "linux")
	base.files[goodTok] = []byte(replayToken + "\n")
	base.modes[goodTok] = 0o600
	base.files[evilCfg] = []byte("{\n  \"enroll_url\": \"https://evil.example\",\n  \"enroll_token_file\": \"" + goodTok + "\"\n}\n")
	base.modes[evilCfg] = 0o600
	before := append([]byte(nil), base.files[evilCfg]...)
	h := &trackHost{memHost: base}
	planPath := PathsFor("", evilCfg).Plan
	evil := replayMemberPlan(t, "https://evil.example", evilCfg, goodTok)
	err := CheckPlanReplay(evil, planPath, h, false)
	if err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatal(err)
	}
	if _, err := Apply(evil, h, ApplyOptions{Token: replayToken, PlanPath: planPath, Replay: true}); err == nil {
		t.Fatal("apply succeeded")
	}
	if !bytes.Equal(base.files[evilCfg], before) || string(base.files[goodTok]) != replayToken+"\n" {
		t.Fatal("files changed")
	}
	if h.stat[goodTok] != 0 || h.read[goodTok] != 0 || h.write[goodTok] != 0 {
		t.Fatalf("touched token stat %v read %v write %v", h.stat, h.read, h.write)
	}
	if len(base.services) != 0 {
		t.Fatal("service installed")
	}
}

func TestPlanReplayRejectsUnownedPlanPath(t *testing.T) {
	cfg := "/home/acme/.idoris/vpn.json"
	paths := PathsFor("", cfg)
	h := newMemHost(false, "linux")
	p := replayMemberPlan(t, "https://enroll.good", cfg, paths.Token)
	if _, err := Apply(p, h, ApplyOptions{Token: replayToken, NoService: true, PlanPath: paths.Plan}); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPlan(bytes.NewReader(h.files[paths.Plan]))
	if err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), h.files[cfg]...)
	err = CheckPlanReplay(loaded, "/tmp/evil-plan.json", h, false)
	if err == nil || !strings.Contains(err.Error(), "not the plan owned by") {
		t.Fatal(err)
	}
	if _, err := Apply(loaded, h, ApplyOptions{Token: replayToken, NoService: true, PlanPath: "/tmp/evil-plan.json", Replay: true}); err == nil {
		t.Fatal("apply succeeded")
	}
	if !bytes.Equal(before, h.files[cfg]) || string(h.files[paths.Token]) != replayToken+"\n" {
		t.Fatal("unowned plan changed the enrollment")
	}
}

func TestPlanReplayReplaceSwitchesOnlyTheNamedConfig(t *testing.T) {
	cfg := "/home/acme/orgA/vpn.json"
	paths := PathsFor("", cfg)
	h := newMemHost(false, "linux")
	p := replayMemberPlan(t, "https://a.example", cfg, paths.Token)
	if _, err := Apply(p, h, ApplyOptions{Token: replayToken, NoService: true, PlanPath: paths.Plan}); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPlan(bytes.NewReader(h.files[paths.Plan]))
	if err != nil {
		t.Fatal(err)
	}
	loaded.EnrollURL = "https://c.example"
	before := append([]byte(nil), h.files[cfg]...)
	tokBefore := append([]byte(nil), h.files[paths.Token]...)
	_, err = Apply(loaded, h, ApplyOptions{Token: replayToken, NoService: true, PlanPath: paths.Plan, Replay: true})
	if err == nil || !strings.Contains(err.Error(), "--replace") {
		t.Fatalf("%v", err)
	}
	if !bytes.Equal(before, h.files[cfg]) || !bytes.Equal(tokBefore, h.files[paths.Token]) {
		t.Fatal("refused replay wrote")
	}
	if _, err := Apply(loaded, h, ApplyOptions{Token: replayToken, NoService: true, PlanPath: paths.Plan, Replay: true, ReplaceExisting: true}); err != nil {
		t.Fatal(err)
	}
	body := h.files[cfg]
	if !bytes.Contains(body, []byte("https://c.example")) || bytes.Contains(body, []byte("https://a.example")) {
		t.Fatalf("config %s", body)
	}
	if string(h.files[paths.Token]) != replayToken+"\n" {
		t.Fatalf("token %q", h.files[paths.Token])
	}
}

func TestPlanReplayAllowsTheTokenTheConfigNames(t *testing.T) {
	cfg := "/home/acme/.idoris/vpn.json"
	tok := "/home/acme/.idoris/enroll.token"
	planPath := PathsFor("", cfg).Plan
	h := newMemHost(false, "linux")
	// The config may store the legacy name as a relative path. The plan's
	// absolute token_file is the same file, not a guess at the sidecar.
	h.files[cfg] = []byte("{\n  \"enroll_url\": \"https://enroll.good\",\n  \"enroll_token_file\": \"enroll.token\"\n}\n")
	h.modes[cfg] = 0o600
	h.files[tok] = []byte(replayToken + "\n")
	h.modes[tok] = 0o600
	p := replayMemberPlan(t, "https://enroll.good", cfg, tok)
	if err := CheckPlanReplay(p, planPath, h, false); err != nil {
		t.Fatal(err)
	}
	p.TokenFile = PathsFor("", cfg).Token
	err := CheckPlanReplay(p, planPath, h, false)
	if err == nil || !strings.Contains(err.Error(), "not the one") {
		t.Fatal(err)
	}
	if string(h.files[tok]) != replayToken+"\n" {
		t.Fatal("naming check rewrote the token")
	}
}

func TestPlanReplayRejectsSpecialFiles(t *testing.T) {
	cfg := "/home/acme/.idoris/vpn.json"
	tok := "/home/acme/.idoris/enroll.token"
	planPath := PathsFor("", cfg).Plan
	body := []byte("{\n  \"enroll_url\": \"https://enroll.good\",\n  \"enroll_token_file\": \"" + tok + "\"\n}\n")
	t.Run("config", func(t *testing.T) {
		base := newMemHost(false, "linux")
		base.files[cfg] = append([]byte(nil), body...)
		base.modes[cfg] = os.ModeNamedPipe
		h := &trackHost{memHost: base}
		p := replayMemberPlan(t, "https://enroll.good", cfg, tok)
		err := CheckPlanReplay(p, planPath, h, false)
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatal(err)
		}
		if h.read[cfg] != 0 || h.read[tok] != 0 {
			t.Fatalf("opened a special file: %#v", h.read)
		}
	})
	t.Run("token", func(t *testing.T) {
		base := newMemHost(false, "linux")
		base.files[cfg] = append([]byte(nil), body...)
		base.modes[cfg] = 0o600
		base.files[tok] = []byte(replayToken + "\n")
		base.modes[tok] = os.ModeNamedPipe
		h := &trackHost{memHost: base}
		p := replayMemberPlan(t, "https://enroll.good", cfg, tok)
		err := CheckPlanReplay(p, planPath, h, false)
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatal(err)
		}
		if h.read[tok] != 0 {
			t.Fatal("opened the special token file")
		}
	})
}

func TestConfirmedApplyStillCreatesAConfig(t *testing.T) {
	cfg := "/home/acme/fresh/vpn.json"
	paths := PathsFor("", cfg)
	h := newMemHost(false, "linux")
	p := replayMemberPlan(t, "https://enroll.good", cfg, paths.Token)
	_, err := Apply(p, h, ApplyOptions{Token: replayToken, NoService: true, PlanPath: paths.Plan, Replay: true})
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("%v", err)
	}
	if _, ok := h.files[cfg]; ok {
		t.Fatal("replay created a config")
	}
	if _, err := Apply(p, h, ApplyOptions{Token: replayToken, NoService: true, PlanPath: paths.Plan}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(h.files[cfg], []byte("https://enroll.good")) || string(h.files[paths.Token]) != replayToken+"\n" {
		t.Fatalf("config %s token %q", h.files[cfg], h.files[paths.Token])
	}
}
