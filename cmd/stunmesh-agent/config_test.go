package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- parseConfigFile: the flat --config file grammar ---

func TestParseConfigFile_BasicKeyValue(t *testing.T) {
	fc, err := parseConfigFile(strings.NewReader("namespace=mymesh-7f3a\nnode_id=alpha\n"))
	if err != nil {
		t.Fatalf("parseConfigFile: %v", err)
	}
	if fc.Namespace == nil || *fc.Namespace != "mymesh-7f3a" {
		t.Errorf("Namespace = %v, want mymesh-7f3a", fc.Namespace)
	}
	if fc.NodeID == nil || *fc.NodeID != "alpha" {
		t.Errorf("NodeID = %v, want alpha", fc.NodeID)
	}
}

func TestParseConfigFile_BlankLinesAndComments(t *testing.T) {
	input := `# this is a comment
namespace=mymesh-7f3a

   # indented comment, ignored
node_id=alpha

`
	fc, err := parseConfigFile(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseConfigFile: %v", err)
	}
	if fc.Namespace == nil || *fc.Namespace != "mymesh-7f3a" {
		t.Errorf("Namespace = %v, want mymesh-7f3a", fc.Namespace)
	}
	if fc.NodeID == nil || *fc.NodeID != "alpha" {
		t.Errorf("NodeID = %v, want alpha", fc.NodeID)
	}
}

func TestParseConfigFile_WhitespaceAroundKeyAndValue(t *testing.T) {
	fc, err := parseConfigFile(strings.NewReader("  namespace  =   mymesh-7f3a  \n"))
	if err != nil {
		t.Fatalf("parseConfigFile: %v", err)
	}
	if fc.Namespace == nil || *fc.Namespace != "mymesh-7f3a" {
		t.Errorf("Namespace = %q, want %q", derefOr(fc.Namespace, "<nil>"), "mymesh-7f3a")
	}
}

func TestParseConfigFile_RepeatableProxy(t *testing.T) {
	input := "proxy=https://a.example\nproxy=https://b.example\n"
	fc, err := parseConfigFile(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseConfigFile: %v", err)
	}
	want := []string{"https://a.example", "https://b.example"}
	if len(fc.Proxies) != len(want) {
		t.Fatalf("Proxies = %v, want %v", fc.Proxies, want)
	}
	for i, p := range want {
		if fc.Proxies[i] != p {
			t.Errorf("Proxies[%d] = %q, want %q", i, fc.Proxies[i], p)
		}
	}
}

func TestParseConfigFile_UnknownKeyRejected(t *testing.T) {
	_, err := parseConfigFile(strings.NewReader("bogus=value\n"))
	if err == nil {
		t.Fatal("parseConfigFile: want error for unknown key, got nil")
	}
	if !strings.Contains(err.Error(), "bogus") {
		t.Errorf("error = %v, want it to name the key %q", err, "bogus")
	}
	if !strings.Contains(err.Error(), "line 1") {
		t.Errorf("error = %v, want it to name the line number", err)
	}
}

func TestParseConfigFile_MalformedLineRejected(t *testing.T) {
	_, err := parseConfigFile(strings.NewReader("namespace=mymesh\nthis has no equals sign\n"))
	if err == nil {
		t.Fatal("parseConfigFile: want error for malformed line, got nil")
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("error = %v, want it to name line 2", err)
	}
}

func TestParseConfigFile_EmptyValueRejected(t *testing.T) {
	_, err := parseConfigFile(strings.NewReader("namespace=\n"))
	if err == nil {
		t.Fatal("parseConfigFile: want error for empty value, got nil")
	}
}

func TestParseConfigFile_DuplicateNonProxyKeyRejected(t *testing.T) {
	_, err := parseConfigFile(strings.NewReader("namespace=a\nnamespace=b\n"))
	if err == nil {
		t.Fatal("parseConfigFile: want error for duplicate key, got nil")
	}
	if !strings.Contains(err.Error(), "namespace") {
		t.Errorf("error = %v, want it to name the key", err)
	}
}

func TestParseConfigFile_ErrorNeverEchoesValue(t *testing.T) {
	_, err := parseConfigFile(strings.NewReader("controller_pubkey=THIS-SECRET-LOOKING-VALUE\ncontroller_pubkey=again\n"))
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), "THIS-SECRET-LOOKING-VALUE") || strings.Contains(err.Error(), "again") {
		t.Errorf("error leaks a value: %v", err)
	}
}

func TestParseConfigFile_AllKnownKeys(t *testing.T) {
	input := strings.Join([]string{
		"namespace=ns",
		"node_id=n1",
		"controller_pubkey=pk",
		"proxy=https://p1.example",
		"identity_key=/tmp/id.key",
		"last=/tmp/last.json",
		"lock=/tmp/lock",
		"stunmesh_config=/tmp/config.yaml",
	}, "\n") + "\n"

	fc, err := parseConfigFile(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseConfigFile: %v", err)
	}
	checks := map[string]*string{
		"namespace":         fc.Namespace,
		"node_id":           fc.NodeID,
		"controller_pubkey": fc.ControllerPubkey,
		"identity_key":      fc.IdentityKey,
		"last":              fc.Last,
		"lock":              fc.Lock,
		"stunmesh_config":   fc.StunmeshConfig,
	}
	for name, got := range checks {
		if got == nil {
			t.Errorf("%s not parsed", name)
		}
	}
	if len(fc.Proxies) != 1 || fc.Proxies[0] != "https://p1.example" {
		t.Errorf("Proxies = %v", fc.Proxies)
	}
}

func derefOr(s *string, fallback string) string {
	if s == nil {
		return fallback
	}
	return *s
}

// --- resolveConfig: flag/--config precedence ---

func newTestFlagSeam(t *testing.T) *flagSeam {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	return registerFlags(fs)
}

func TestResolveConfig_FlagWinsOverConfigFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.conf")
	writeFile(t, configPath, "namespace=from-file\n")

	seam := newTestFlagSeam(t)
	if err := seam.fs.Parse([]string{"--namespace", "from-flag", "--config", configPath}); err != nil {
		t.Fatalf("Parse: %v", err)
	}

	cfg, err := resolveConfig(seam)
	if err != nil {
		t.Fatalf("resolveConfig: %v", err)
	}
	if cfg.Namespace != "from-flag" {
		t.Errorf("Namespace = %q, want %q (flag must win)", cfg.Namespace, "from-flag")
	}
}

func TestResolveConfig_ConfigFileFillsWhatFlagOmits(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.conf")
	writeFile(t, configPath, "namespace=from-file\nnode_id=n1\n")

	seam := newTestFlagSeam(t)
	if err := seam.fs.Parse([]string{"--config", configPath}); err != nil {
		t.Fatalf("Parse: %v", err)
	}

	cfg, err := resolveConfig(seam)
	if err != nil {
		t.Fatalf("resolveConfig: %v", err)
	}
	if cfg.Namespace != "from-file" {
		t.Errorf("Namespace = %q, want %q", cfg.Namespace, "from-file")
	}
	if cfg.NodeID != "n1" {
		t.Errorf("NodeID = %q, want %q", cfg.NodeID, "n1")
	}
}

func TestResolveConfig_ProxyFlagReplacesConfigFileProxiesEntirely(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.conf")
	writeFile(t, configPath, "proxy=https://file1.example\nproxy=https://file2.example\n")

	seam := newTestFlagSeam(t)
	if err := seam.fs.Parse([]string{"--proxy", "https://flag1.example", "--config", configPath}); err != nil {
		t.Fatalf("Parse: %v", err)
	}

	cfg, err := resolveConfig(seam)
	if err != nil {
		t.Fatalf("resolveConfig: %v", err)
	}
	if len(cfg.Proxies) != 1 || cfg.Proxies[0] != "https://flag1.example" {
		t.Errorf("Proxies = %v, want exactly the flag's list", cfg.Proxies)
	}
}

func TestResolveConfig_ConfigFileProxiesUsedWhenNoProxyFlag(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.conf")
	writeFile(t, configPath, "proxy=https://file1.example\nproxy=https://file2.example\n")

	seam := newTestFlagSeam(t)
	if err := seam.fs.Parse([]string{"--config", configPath}); err != nil {
		t.Fatalf("Parse: %v", err)
	}

	cfg, err := resolveConfig(seam)
	if err != nil {
		t.Fatalf("resolveConfig: %v", err)
	}
	want := []string{"https://file1.example", "https://file2.example"}
	if len(cfg.Proxies) != len(want) {
		t.Fatalf("Proxies = %v, want %v", cfg.Proxies, want)
	}
	for i := range want {
		if cfg.Proxies[i] != want[i] {
			t.Errorf("Proxies[%d] = %q, want %q", i, cfg.Proxies[i], want[i])
		}
	}
}

func TestResolveConfig_DefaultProxiesWhenNeitherFlagNorFileGiven(t *testing.T) {
	seam := newTestFlagSeam(t)
	if err := seam.fs.Parse(nil); err != nil {
		t.Fatalf("Parse: %v", err)
	}

	cfg, err := resolveConfig(seam)
	if err != nil {
		t.Fatalf("resolveConfig: %v", err)
	}
	if len(cfg.Proxies) != len(defaultProxies) {
		t.Fatalf("Proxies = %v, want %v", cfg.Proxies, defaultProxies)
	}
	for i := range defaultProxies {
		if cfg.Proxies[i] != defaultProxies[i] {
			t.Errorf("Proxies[%d] = %q, want %q", i, cfg.Proxies[i], defaultProxies[i])
		}
	}
}

func TestResolveConfig_DefaultPathsWhenNeitherFlagNorFileGiven(t *testing.T) {
	seam := newTestFlagSeam(t)
	if err := seam.fs.Parse(nil); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg, err := resolveConfig(seam)
	if err != nil {
		t.Fatalf("resolveConfig: %v", err)
	}
	if cfg.LastPath != defaultLastPath {
		t.Errorf("LastPath = %q, want %q", cfg.LastPath, defaultLastPath)
	}
	if cfg.LockPath != defaultLockPath {
		t.Errorf("LockPath = %q, want %q", cfg.LockPath, defaultLockPath)
	}
	if cfg.StunmeshConfigPath != defaultStunmeshConfigPath {
		t.Errorf("StunmeshConfigPath = %q, want %q", cfg.StunmeshConfigPath, defaultStunmeshConfigPath)
	}
}

func TestResolveConfig_ConfigFilePathOverridesDefault(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.conf")
	writeFile(t, configPath, "last=/custom/last.json\n")

	seam := newTestFlagSeam(t)
	if err := seam.fs.Parse([]string{"--config", configPath}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg, err := resolveConfig(seam)
	if err != nil {
		t.Fatalf("resolveConfig: %v", err)
	}
	if cfg.LastPath != "/custom/last.json" {
		t.Errorf("LastPath = %q, want %q", cfg.LastPath, "/custom/last.json")
	}
}

func TestResolveConfig_MissingConfigFileIsAnError(t *testing.T) {
	seam := newTestFlagSeam(t)
	if err := seam.fs.Parse([]string{"--config", "/no/such/file"}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := resolveConfig(seam); err == nil {
		t.Fatal("resolveConfig: want error for a missing --config file, got nil")
	}
}

func TestResolveConfig_BadConfigFileIsAnError(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.conf")
	writeFile(t, configPath, "not a valid line\n")

	seam := newTestFlagSeam(t)
	if err := seam.fs.Parse([]string{"--config", configPath}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := resolveConfig(seam); err == nil {
		t.Fatal("resolveConfig: want error for a malformed --config file, got nil")
	}
}

// --- Config validation ---

func TestValidateFetch_ReportsAllMissingSettings(t *testing.T) {
	cfg := &Config{}
	err := cfg.ValidateFetch()
	if err == nil {
		t.Fatal("ValidateFetch: want error, got nil")
	}
	for _, want := range []string{"--namespace", "--node-id", "--controller-pubkey", "--identity-key"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to mention %q", err, want)
		}
	}
}

func TestValidateFetch_RejectsBadControllerPubkey(t *testing.T) {
	cfg := &Config{
		Namespace:          "ns",
		NodeID:             "n1",
		ControllerPubkey:   "not-base64-32-bytes",
		IdentityKeyPath:    "/tmp/id.key",
		Proxies:            []string{"https://p.example"},
		LastPath:           defaultLastPath,
		LockPath:           defaultLockPath,
		StunmeshConfigPath: defaultStunmeshConfigPath,
	}
	err := cfg.ValidateFetch()
	if err == nil {
		t.Fatal("ValidateFetch: want error for a bad controller pubkey, got nil")
	}
	if strings.Contains(err.Error(), "not-base64-32-bytes") {
		t.Errorf("error leaks the bad value: %v", err)
	}
}

func TestValidateFetch_OKWithEverythingSet(t *testing.T) {
	cfg := &Config{
		Namespace:          "ns",
		NodeID:             "n1",
		ControllerPubkey:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		IdentityKeyPath:    "/tmp/id.key",
		Proxies:            []string{"https://p.example"},
		LastPath:           defaultLastPath,
		LockPath:           defaultLockPath,
		StunmeshConfigPath: defaultStunmeshConfigPath,
	}
	if err := cfg.ValidateFetch(); err != nil {
		t.Errorf("ValidateFetch: %v, want nil", err)
	}
}

func TestValidateKeygen_RequiresOnlyIdentityKey(t *testing.T) {
	cfg := &Config{}
	if err := cfg.ValidateKeygen(); err == nil {
		t.Fatal("ValidateKeygen: want error when --identity-key is missing, got nil")
	}

	cfg.IdentityKeyPath = "/tmp/id.key"
	if err := cfg.ValidateKeygen(); err != nil {
		t.Errorf("ValidateKeygen: %v, want nil (namespace/node-id/controller-pubkey/proxy must not be required)", err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
