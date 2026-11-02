package gateway

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CheckPlanReplay decides whether `gateway apply --plan` may reuse an
// on-disk token. Every field in the plan is chosen by whoever wrote the
// file, so enroll_url, token_file, and config_path are not authority.
//
// A replay may continue only when the plan path is the canonical plan of
// plan.ConfigPath and that config already records the same enroll URL and
// the same token file. The token path has to stay inside the config's
// directory. A missing config, a token from another directory, or a legacy
// shared token this config does not already name is refused. --replace may
// switch the URL of this same config; it does not adopt a new config_path
// or a different token file.
//
// The token file is stated, not read. A fifo or other special file is
// refused before anyone opens it.
func CheckPlanReplay(plan Plan, planPath string, host Host, replace bool) error {
	if host == nil {
		return errors.New("gateway: host is nil")
	}
	configPath := filepath.Clean(strings.TrimSpace(plan.ConfigPath))
	if configPath == "" || configPath == "." {
		return errors.New("gateway: refusing plan replay: plan is missing config_path")
	}
	planPath = strings.TrimSpace(planPath)
	if planPath == "" {
		return errors.New("gateway: refusing plan replay: plan path is empty")
	}
	gotPlan, err := filepath.Abs(planPath)
	if err != nil {
		return fmt.Errorf("gateway: plan path: %w", err)
	}
	wantPlan, err := filepath.Abs(PathsFor("", configPath).Plan)
	if err != nil {
		return fmt.Errorf("gateway: plan path: %w", err)
	}
	if filepath.Clean(gotPlan) != filepath.Clean(wantPlan) {
		return fmt.Errorf("gateway: refusing plan %s: it is not the plan owned by %s", planPath, configPath)
	}
	info, err := host.Stat(configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("gateway: refusing plan replay: %s does not exist", configPath)
		}
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("gateway: config %s is not a regular file", configPath)
	}
	existing, have, err := readExistingConfig(host, configPath)
	if err != nil {
		return err
	}
	if !have {
		return fmt.Errorf("gateway: refusing plan replay: %s has no enrollment", configPath)
	}
	oldURL, hasURL := jsonStringField(existing, "enroll_url")
	if !hasURL || strings.TrimSpace(oldURL) == "" {
		return fmt.Errorf("gateway: refusing plan replay: %s has no enroll_url", configPath)
	}
	newURL := strings.TrimSpace(plan.EnrollURL)
	if newURL == "" {
		return errors.New("gateway: refusing plan replay: plan has no enroll_url")
	}
	pointer, hasPointer := jsonStringField(existing, "enroll_token_file")
	if !hasPointer || strings.TrimSpace(pointer) == "" {
		return fmt.Errorf("gateway: refusing plan replay: %s has no enroll_token_file", configPath)
	}
	named := resolveTokenRef(configPath, pointer)
	tok := resolveTokenRef(configPath, plan.TokenFile)
	if tok == "" {
		return errors.New("gateway: refusing plan replay: plan is missing token_file")
	}
	if err := tokenInConfigDir(configPath, tok); err != nil {
		return err
	}
	if tok != named {
		return fmt.Errorf("gateway: refusing plan replay: token file %s is not the one %s names", tok, configPath)
	}
	// URL mismatch is checked after the token is known to belong to this
	// config, and before that file is opened. --replace is the existing
	// explicit switch for this config only.
	if oldURL != plan.EnrollURL && !replace {
		return fmt.Errorf("gateway: %s is already enrolled with %s; pass --replace to switch it to %s", configPath, oldURL, plan.EnrollURL)
	}
	tokInfo, err := host.Stat(tok)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("gateway: refusing plan replay: token file %s does not exist", tok)
		}
		return err
	}
	if !tokInfo.Mode().IsRegular() {
		return fmt.Errorf("gateway: token file %s is not a regular file", tok)
	}
	return nil
}

// tokenInConfigDir rejects a token path that is not a file directly in the
// config's directory. A cleaned absolute path outside that directory, or a
// nested relative path, is a substitution. Ownership is not inferred by
// scanning other directories.
func tokenInConfigDir(configPath, tokenPath string) error {
	dir := filepath.Clean(filepath.Dir(configPath))
	tok := filepath.Clean(tokenPath)
	rel, err := filepath.Rel(dir, tok)
	nested := err == nil && strings.ContainsRune(rel, filepath.Separator)
	if err != nil || rel == "." || rel == ".." || nested || filepath.IsAbs(rel) {
		return fmt.Errorf("gateway: refusing plan replay: token file %s is outside %s", tok, dir)
	}
	return nil
}
