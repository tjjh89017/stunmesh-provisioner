package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}
	return path
}

const validPubkey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func minimalConfigYAML() string {
	return "namespace: ns\nnode_id: n1\ncontroller_pubkey: " + validPubkey + "\n"
}

func TestFindConfigFile_ExactFileMustExist(t *testing.T) {
	if _, err := findConfigFile(filepath.Join(t.TempDir(), "missing.yaml"), ""); err == nil {
		t.Errorf("err = nil, want an error for a missing --config file")
	}
}

func TestFindConfigFile_ExactFileFound(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, minimalConfigYAML())
	got, err := findConfigFile(path, "/does/not/matter")
	if err != nil {
		t.Fatalf("findConfigFile: %v", err)
	}
	if got != path {
		t.Errorf("got %q, want %q", got, path)
	}
}

func TestFindConfigFile_SearchesConfigDir(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, minimalConfigYAML())
	got, err := findConfigFile("", dir)
	if err != nil {
		t.Fatalf("findConfigFile: %v", err)
	}
	if got != path {
		t.Errorf("got %q, want %q", got, path)
	}
}

func TestFindConfigFile_MissingInDirIsNotAnError(t *testing.T) {
	got, err := findConfigFile("", t.TempDir())
	if err != nil {
		t.Fatalf("findConfigFile: %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want empty (not provisioned yet)", got)
	}
}

func TestFindConfigFile_PrefersYamlOverYml(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yml"), []byte(minimalConfigYAML()), 0o600); err != nil {
		t.Fatalf("write config.yml: %v", err)
	}
	yamlPath := writeConfig(t, dir, minimalConfigYAML())
	got, err := findConfigFile("", dir)
	if err != nil {
		t.Fatalf("findConfigFile: %v", err)
	}
	if got != yamlPath {
		t.Errorf("got %q, want config.yaml preferred over config.yml", got)
	}
}

func TestLoadConfig_MinimalDefaults(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, minimalConfigYAML())

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Namespace != "ns" || cfg.NodeID != "n1" || cfg.ControllerPubkey != validPubkey {
		t.Errorf("cfg = %+v, want the three required fields set", cfg)
	}
	if cfg.RefreshInterval != defaultRefreshInterval {
		t.Errorf("RefreshInterval = %v, want %v", cfg.RefreshInterval, defaultRefreshInterval)
	}
	if cfg.FullApplyInterval != defaultFullApplyInterval {
		t.Errorf("FullApplyInterval = %v, want %v", cfg.FullApplyInterval, defaultFullApplyInterval)
	}
	if cfg.IdentityKeyPath != filepath.Join(dir, "identity.key") {
		t.Errorf("IdentityKeyPath = %q, want alongside config.yaml", cfg.IdentityKeyPath)
	}
	if cfg.LastPath != filepath.Join(dir, "last.json") {
		t.Errorf("LastPath = %q, want alongside config.yaml", cfg.LastPath)
	}
	if cfg.LockPath != defaultLockPath {
		t.Errorf("LockPath = %q, want %q", cfg.LockPath, defaultLockPath)
	}
	if len(cfg.Proxies) != len(defaultProxies) {
		t.Errorf("Proxies = %v, want the built-in default list", cfg.Proxies)
	}
	if cfg.Stunmesh.WritePath != defaultStunmeshConfigPath {
		t.Errorf("Stunmesh.WritePath = %q, want %q", cfg.Stunmesh.WritePath, defaultStunmeshConfigPath)
	}
	if cfg.Stunmesh.AppOptions.ConfigFile != defaultStunmeshConfigPath {
		t.Errorf("Stunmesh.AppOptions.ConfigFile = %q, want %q", cfg.Stunmesh.AppOptions.ConfigFile, defaultStunmeshConfigPath)
	}
}

func TestLoadConfig_MissingRequiredKeys(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "namespace: ns\n")

	_, err := loadConfig(path)
	if err == nil {
		t.Fatal("err = nil, want an error naming the missing keys")
	}
	if !strings.Contains(err.Error(), "node_id") || !strings.Contains(err.Error(), "controller_pubkey") {
		t.Errorf("err = %v, want it to name both missing keys", err)
	}
}

func TestLoadConfig_UnknownKeyRejected(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, minimalConfigYAML()+"bogus_key: 1\n")

	_, err := loadConfig(path)
	if err == nil {
		t.Fatal("err = nil, want an error for an unknown key")
	}
	if !strings.Contains(err.Error(), "bogus_key") {
		t.Errorf("err = %v, want it to name the unknown key", err)
	}
}

func TestLoadConfig_BadControllerPubkeyNeverEchoed(t *testing.T) {
	dir := t.TempDir()
	sentinel := "sentinel-not-a-real-key-B64=="
	path := writeConfig(t, dir, "namespace: ns\nnode_id: n1\ncontroller_pubkey: "+sentinel+"\n")

	_, err := loadConfig(path)
	if err == nil {
		t.Fatal("err = nil, want an error for a bad controller_pubkey")
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Errorf("err = %v, leaked the bad key value", err)
	}
}

func TestLoadConfig_RefreshIntervalZeroIsError(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, minimalConfigYAML()+"refresh_interval: 0\n")
	if _, err := loadConfig(path); err == nil {
		t.Fatal("err = nil, want refresh_interval: 0 to be rejected")
	}
}

func TestLoadConfig_FullApplyIntervalZeroDisablesIt(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, minimalConfigYAML()+"full_apply_interval: 0\n")
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.FullApplyInterval != 0 {
		t.Errorf("FullApplyInterval = %v, want 0 (disabled)", cfg.FullApplyInterval)
	}
}

func TestLoadConfig_FullApplyIntervalNegativeIsError(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, minimalConfigYAML()+"full_apply_interval: -1h\n")
	if _, err := loadConfig(path); err == nil {
		t.Fatal("err = nil, want a negative full_apply_interval to be rejected")
	}
}

func TestLoadConfig_ExplicitPathsOverrideDefaults(t *testing.T) {
	dir := t.TempDir()
	otherDir := t.TempDir()
	yaml := minimalConfigYAML() +
		"identity_key: " + filepath.Join(otherDir, "id.key") + "\n" +
		"last: " + filepath.Join(otherDir, "last.json") + "\n" +
		"lock: " + filepath.Join(otherDir, "agent.lock") + "\n"
	path := writeConfig(t, dir, yaml)

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.IdentityKeyPath != filepath.Join(otherDir, "id.key") {
		t.Errorf("IdentityKeyPath = %q", cfg.IdentityKeyPath)
	}
	if cfg.LastPath != filepath.Join(otherDir, "last.json") {
		t.Errorf("LastPath = %q", cfg.LastPath)
	}
	if cfg.LockPath != filepath.Join(otherDir, "agent.lock") {
		t.Errorf("LockPath = %q", cfg.LockPath)
	}
}

func TestLoadConfig_UsePluginResolvesBackend(t *testing.T) {
	dir := t.TempDir()
	yaml := minimalConfigYAML() +
		"use_plugin: mydht\n" +
		"plugins:\n" +
		"  mydht:\n" +
		"    type: dhtproxy\n" +
		"    proxies:\n" +
		"      - https://example.invalid/proxy\n"
	path := writeConfig(t, dir, yaml)

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if len(cfg.Proxies) != 1 || cfg.Proxies[0] != "https://example.invalid/proxy" {
		t.Errorf("Proxies = %v, want the one configured proxy", cfg.Proxies)
	}
}

func TestLoadConfig_UsePluginMissingEntryIsError(t *testing.T) {
	dir := t.TempDir()
	yaml := minimalConfigYAML() + "use_plugin: mydht\n"
	path := writeConfig(t, dir, yaml)

	_, err := loadConfig(path)
	if err == nil {
		t.Fatal("err = nil, want use_plugin naming a missing entry to be rejected")
	}
}

func TestResolveStunmeshConfig_ConfigFileWins(t *testing.T) {
	rs := &rawStunmesh{Config: strptr("/etc/stunmesh/custom.yaml"), ConfigDir: strptr("/etc/stunmesh/dir")}
	got := resolveStunmeshConfig(rs)
	if got.WritePath != "/etc/stunmesh/custom.yaml" {
		t.Errorf("WritePath = %q", got.WritePath)
	}
	if got.AppOptions.ConfigFile != "/etc/stunmesh/custom.yaml" || got.AppOptions.ConfigDir != "" {
		t.Errorf("AppOptions = %+v, want only ConfigFile set", got.AppOptions)
	}
}

func TestResolveStunmeshConfig_ConfigDirOnly(t *testing.T) {
	rs := &rawStunmesh{ConfigDir: strptr("/etc/stunmesh")}
	got := resolveStunmeshConfig(rs)
	if got.WritePath != filepath.Join("/etc/stunmesh", "config.yaml") {
		t.Errorf("WritePath = %q", got.WritePath)
	}
	if got.AppOptions.ConfigDir != "/etc/stunmesh" || got.AppOptions.ConfigFile != "" {
		t.Errorf("AppOptions = %+v, want only ConfigDir set", got.AppOptions)
	}
}

func TestResolveStunmeshConfig_NilUsesDefault(t *testing.T) {
	got := resolveStunmeshConfig(nil)
	if got.WritePath != defaultStunmeshConfigPath {
		t.Errorf("WritePath = %q, want %q", got.WritePath, defaultStunmeshConfigPath)
	}
}

func TestLoadStunmeshOnlyConfig_EmptyPathUsesDefaults(t *testing.T) {
	got, err := loadStunmeshOnlyConfig("")
	if err != nil {
		t.Fatalf("loadStunmeshOnlyConfig: %v", err)
	}
	if got.WritePath != defaultStunmeshConfigPath {
		t.Errorf("WritePath = %q, want %q", got.WritePath, defaultStunmeshConfigPath)
	}
}

// TestLoadStunmeshOnlyConfig_IgnoresOtherRequiredFields proves
// --stunmesh-only never needs namespace/node_id/controller_pubkey:
// a config.yaml missing all three, but with a "stunmesh" section, is
// still accepted.
func TestLoadStunmeshOnlyConfig_IgnoresOtherRequiredFields(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "stunmesh:\n  config_dir: /etc/stunmesh\n")

	got, err := loadStunmeshOnlyConfig(path)
	if err != nil {
		t.Fatalf("loadStunmeshOnlyConfig: %v", err)
	}
	if got.AppOptions.ConfigDir != "/etc/stunmesh" {
		t.Errorf("AppOptions.ConfigDir = %q", got.AppOptions.ConfigDir)
	}
}

func strptr(s string) *string { return &s }
