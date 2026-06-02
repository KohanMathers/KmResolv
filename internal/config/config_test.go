package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaults(t *testing.T) {
	cfg := defaults()

	if cfg.Server.Listen != "0.0.0.0" {
		t.Errorf("listen = %q, want 0.0.0.0", cfg.Server.Listen)
	}
	if cfg.Server.Port != 53 {
		t.Errorf("port = %d, want 53", cfg.Server.Port)
	}
	if cfg.Server.LogLevel != "info" {
		t.Errorf("log_level = %q, want info", cfg.Server.LogLevel)
	}
	if cfg.Resolver.Timeout != 3 {
		t.Errorf("timeout = %d, want 3", cfg.Resolver.Timeout)
	}
	if cfg.Resolver.MaxDepth != 20 {
		t.Errorf("max_depth = %d, want 20", cfg.Resolver.MaxDepth)
	}
	if !cfg.Resolver.EDNS0 {
		t.Error("edns0 should default to true")
	}
	if !cfg.Resolver.TCPFallback {
		t.Error("tcp_fallback should default to true")
	}
	if !cfg.Resolver.RateLimit.Enabled {
		t.Error("rate_limit.enabled should default to true")
	}
	if cfg.Resolver.RateLimit.QPS != 100 {
		t.Errorf("rate_limit.qps = %d, want 100", cfg.Resolver.RateLimit.QPS)
	}
	if cfg.Resolver.RateLimit.Burst != 200 {
		t.Errorf("rate_limit.burst = %d, want 200", cfg.Resolver.RateLimit.Burst)
	}
	if !cfg.Resolver.Cache.Enabled {
		t.Error("cache.enabled should default to true")
	}
	if cfg.Resolver.Cache.NegativeTTL != 300 {
		t.Errorf("negative_ttl = %d, want 300", cfg.Resolver.Cache.NegativeTTL)
	}
	if !cfg.Resolver.Cache.Prefetch {
		t.Error("cache.prefetch should default to true")
	}
	if cfg.Filtering.Mode != "off" {
		t.Errorf("filter mode = %q, want off", cfg.Filtering.Mode)
	}
	if !cfg.Dashboard.Enabled {
		t.Error("dashboard.enabled should default to true")
	}
	if cfg.Dashboard.Listen != "127.0.0.1" {
		t.Errorf("dashboard.listen = %q, want 127.0.0.1", cfg.Dashboard.Listen)
	}
	if cfg.Dashboard.Port != 8080 {
		t.Errorf("dashboard.port = %d, want 8080", cfg.Dashboard.Port)
	}
	if !cfg.Updater.CheckEnabled {
		t.Error("updater.check_enabled should default to true")
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	cfg, err := LoadConfig("/nonexistent/path/config.yml")
	if err != nil {
		t.Fatalf("missing file should return defaults without error, got: %v", err)
	}
	if cfg.Server.Port != 53 {
		t.Errorf("expected default port 53, got %d", cfg.Server.Port)
	}
}

func TestLoadConfigValidYAML(t *testing.T) {
	path := writeConfig(t, `
server:
  listen: "127.0.0.1"
  port: 5353
  log_level: "debug"
filtering:
  mode: "blacklist"
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Listen != "127.0.0.1" {
		t.Errorf("listen = %q, want 127.0.0.1", cfg.Server.Listen)
	}
	if cfg.Server.Port != 5353 {
		t.Errorf("port = %d, want 5353", cfg.Server.Port)
	}
	if cfg.Server.LogLevel != "debug" {
		t.Errorf("log_level = %q, want debug", cfg.Server.LogLevel)
	}
	if cfg.Filtering.Mode != "blacklist" {
		t.Errorf("filter mode = %q, want blacklist", cfg.Filtering.Mode)
	}
	if cfg.Resolver.Timeout != 3 {
		t.Errorf("unspecified timeout should remain default 3, got %d", cfg.Resolver.Timeout)
	}
}

func TestLoadConfigMalformedYAML(t *testing.T) {
	path := writeConfig(t, "{{invalid yaml:::")
	_, err := LoadConfig(path)
	if err == nil {
		t.Error("malformed YAML should return error")
	}
}

func TestLoadConfigInvalidPort(t *testing.T) {
	path := writeConfig(t, "server:\n  port: 0\nfiltering:\n  mode: off\n")
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("port 0 should fail validation")
	}
}

func TestLoadConfigPortTooHigh(t *testing.T) {
	path := writeConfig(t, "server:\n  port: 65536\nfiltering:\n  mode: off\n")
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("port 65536 should fail validation")
	}
}

func TestLoadConfigInvalidFilterMode(t *testing.T) {
	path := writeConfig(t, "server:\n  port: 53\nfiltering:\n  mode: invalid\n")
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("invalid filter mode should fail validation")
	}
}

func TestLoadConfigInvalidRateLimit(t *testing.T) {
	path := writeConfig(t, `
server:
  port: 53
resolver:
  rate_limit:
    enabled: true
    qps: 0
    burst: 10
filtering:
  mode: off
`)
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("enabled rate limiter with qps 0 should fail validation")
	}
}

func TestLoadConfigUnknownRecordTypeIsAllowed(t *testing.T) {
	path := writeConfig(t, `
server:
  port: 53
filtering:
  mode: "off"
records:
  - name: "test.com"
    type: "BOGUS"
    ttl: 60
    value: "1.2.3.4"
`)
	_, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unknown record type should not fail config load: %v", err)
	}
}

func TestLoadConfigMissingRecordValue(t *testing.T) {
	path := writeConfig(t, `
server:
  port: 53
filtering:
  mode: "off"
records:
  - name: "test.com"
    type: "A"
    ttl: 60
    value: ""
`)
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("record with empty value should fail validation")
	}
}

func TestLoadConfigSupportedRecordTypes(t *testing.T) {
	for _, rtype := range []string{"A", "AAAA", "CNAME", "TXT", "MX",
		"PTR", "NS", "SRV", "CAA", "CERT", "DNSKEY", "DS",
		"HTTPS", "SVCB", "LOC", "NAPTR", "OPENPGPKEY", "SMIMEA",
		"SSHFP", "TLSA", "URI"} {
		path := writeConfig(t, fmt.Sprintf(`
server:
  port: 53
filtering:
  mode: "off"
records:
  - name: "test.com"
    type: "%s"
    ttl: 60
    value: "placeholder"
`, rtype))
		_, err := LoadConfig(path)
		if err != nil {
			t.Errorf("record type %q should pass validation, got: %v", rtype, err)
		}
	}
}

func TestAddr(t *testing.T) {
	cfg := &Config{Server: ServerConfig{Listen: "0.0.0.0", Port: 53}}
	if cfg.Addr() != "0.0.0.0:53" {
		t.Errorf("Addr() = %q, want 0.0.0.0:53", cfg.Addr())
	}
}

func TestDashboardAddr(t *testing.T) {
	cfg := &Config{Dashboard: DashboardConfig{Listen: "127.0.0.1", Port: 8080}}
	if cfg.DashboardAddr() != "127.0.0.1:8080" {
		t.Errorf("DashboardAddr() = %q, want 127.0.0.1:8080", cfg.DashboardAddr())
	}
}

func TestAuthEnabled(t *testing.T) {
	cfg := &Config{}
	if cfg.AuthEnabled() {
		t.Error("auth should not be enabled with empty credentials")
	}

	cfg.Dashboard.Auth = AuthConfig{Username: "admin"}
	if cfg.AuthEnabled() {
		t.Error("auth should not be enabled with only username set")
	}

	cfg.Dashboard.Auth = AuthConfig{Password: "secret"}
	if cfg.AuthEnabled() {
		t.Error("auth should not be enabled with only password set")
	}

	cfg.Dashboard.Auth = AuthConfig{Username: "admin", Password: "secret"}
	if !cfg.AuthEnabled() {
		t.Error("auth should be enabled when both username and password are set")
	}
}

func TestSaveNoPath(t *testing.T) {
	cfg := &Config{}
	if err := cfg.Save(); err == nil {
		t.Error("Save with no path should return error")
	}
}

func TestSaveRoundTrip(t *testing.T) {
	path := writeConfig(t, "server:\n  port: 53\nfiltering:\n  mode: off\n")

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	cfg.Server.Port = 5555
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	cfg2, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if cfg2.Server.Port != 5555 {
		t.Errorf("reloaded port = %d, want 5555", cfg2.Server.Port)
	}
}

func TestValidate(t *testing.T) {
	valid := Config{
		Server:    ServerConfig{Port: 53},
		Filtering: FilterConfig{Mode: "off"},
	}

	if err := valid.validate(); err != nil {
		t.Errorf("valid config failed validation: %v", err)
	}

	portZero := valid
	portZero.Server.Port = 0
	if err := portZero.validate(); err == nil {
		t.Error("port 0 should fail validation")
	}

	portHigh := valid
	portHigh.Server.Port = 65536
	if err := portHigh.validate(); err == nil {
		t.Error("port 65536 should fail validation")
	}

	badMode := valid
	badMode.Filtering.Mode = "invalid"
	if err := badMode.validate(); err == nil {
		t.Error("invalid filter mode should fail validation")
	}

	badRate := valid
	badRate.Resolver.RateLimit = RateLimitConfig{Enabled: true, QPS: -1, Burst: 10}
	if err := badRate.validate(); err == nil {
		t.Error("negative rate limit qps should fail validation")
	}

	badBurst := valid
	badBurst.Resolver.RateLimit = RateLimitConfig{Enabled: true, QPS: 10, Burst: 0}
	if err := badBurst.validate(); err == nil {
		t.Error("enabled rate limiter with burst 0 should fail validation")
	}

	unknownType := valid
	unknownType.Records = []RecordConfig{{Name: "t.com", Type: "BOGUS", Value: "x"}}
	if err := unknownType.validate(); err != nil {
		t.Errorf("unknown record type should pass validation (skipped at runtime): %v", err)
	}

	missingRecordName := valid
	missingRecordName.Records = []RecordConfig{{Name: "", Type: "A", Value: "1.2.3.4"}}
	if err := missingRecordName.validate(); err == nil {
		t.Error("record with empty name should fail validation")
	}
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}
