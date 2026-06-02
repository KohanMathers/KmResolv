package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	path      string
	Server    ServerConfig    `yaml:"server"`
	Resolver  ResolverConfig  `yaml:"resolver"`
	Records   []RecordConfig  `yaml:"records"`
	Filtering FilterConfig    `yaml:"filtering"`
	Dashboard DashboardConfig `yaml:"dashboard"`
	Updater   UpdaterConfig   `yaml:"updater"`
	Minecraft MinecraftConfig `yaml:"minecraft"`
}

type ServerConfig struct {
	Listen       string `yaml:"listen"`
	Port         int    `yaml:"port"`
	LogLevel     string `yaml:"log_level"`
	QueryLogFile string `yaml:"query_log_file"`
}

type ResolverConfig struct {
	Timeout          int             `yaml:"timeout"`
	AttemptTimeoutMs int             `yaml:"attempt_timeout_ms"`
	MaxDepth         int             `yaml:"max_depth"`
	MaxConcurrent    int             `yaml:"max_concurrent"`
	EDNS0            bool            `yaml:"edns0"`
	TCPFallback      bool            `yaml:"tcp_fallback"`
	DNSSEC           bool            `yaml:"dnssec"`
	RateLimit        RateLimitConfig `yaml:"rate_limit"`
	Cache            CacheConfig     `yaml:"cache"`
	Forwarder        ForwarderConfig `yaml:"forwarder"`
}

type RateLimitConfig struct {
	Enabled bool `yaml:"enabled"`
	QPS     int  `yaml:"qps"`
	Burst   int  `yaml:"burst"`
}

type ForwarderConfig struct {
	Enabled             bool     `yaml:"enabled"`
	Servers             []string `yaml:"servers"`
	FallbackToIterative bool     `yaml:"fallback_to_iterative"`
}

type CacheConfig struct {
	Enabled     bool `yaml:"enabled"`
	NegativeTTL int  `yaml:"negative_ttl"`
	Prefetch    bool `yaml:"prefetch"`
	MinTTL      int  `yaml:"min_ttl"`
	MaxSize     int  `yaml:"max_size"`
}

type RecordConfig struct {
	Name  string `yaml:"name"`
	Type  string `yaml:"type"`
	TTL   uint32 `yaml:"ttl"`
	Value string `yaml:"value"`
}

type FilterConfig struct {
	Mode                string   `yaml:"mode"`
	Inline              []string `yaml:"inline"`
	Lists               []string `yaml:"lists"`
	ReloadIntervalHours int      `yaml:"reload_interval_hours"`
}

type DashboardConfig struct {
	Enabled     bool       `yaml:"enabled"`
	Listen      string     `yaml:"listen"`
	Port        int        `yaml:"port"`
	Auth        AuthConfig `yaml:"auth"`
	TLSCertFile string     `yaml:"tls_cert_file"`
	TLSKeyFile  string     `yaml:"tls_key_file"`
}

type AuthConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type UpdaterConfig struct {
	CheckEnabled bool `yaml:"check_enabled"`
}

type MinecraftConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
	Port    int    `yaml:"port"`
	MinRAM  string `yaml:"min_ram"`
	MaxRAM  string `yaml:"max_ram"`
}

func defaults() Config {
	return Config{
		Server: ServerConfig{
			Listen:   "0.0.0.0",
			Port:     53,
			LogLevel: "info",
		},
		Resolver: ResolverConfig{
			Timeout:          3,
			AttemptTimeoutMs: 800,
			MaxDepth:         20,
			MaxConcurrent:    64,
			EDNS0:            true,
			TCPFallback:      true,
			RateLimit: RateLimitConfig{
				Enabled: true,
				QPS:     100,
				Burst:   200,
			},
			Cache: CacheConfig{
				Enabled:     true,
				NegativeTTL: 300,
				Prefetch:    true,
				MinTTL:      30,
			},
			Forwarder: ForwarderConfig{
				Enabled:             false,
				Servers:             []string{"1.1.1.1", "8.8.8.8"},
				FallbackToIterative: true,
			},
		},
		Filtering: FilterConfig{
			Mode: "off",
		},
		Dashboard: DashboardConfig{
			Enabled: true,
			Listen:  "127.0.0.1",
			Port:    8080,
		},
		Minecraft: MinecraftConfig{
			Enabled: false,
			Listen:  "0.0.0.0",
			Port:    25565,
			MinRAM:  "1G",
			MaxRAM:  "2G",
		},
		Updater: UpdaterConfig{
			CheckEnabled: true,
		},
	}
}

func LoadConfig(path string) (*Config, error) {
	cfg := defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	cfg.path = path
	return &cfg, nil
}

func (c *Config) validate() error {
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port %d out of range", c.Server.Port)
	}
	if c.Resolver.RateLimit.QPS < 0 {
		return fmt.Errorf("resolver.rate_limit.qps must be >= 0")
	}
	if c.Resolver.RateLimit.Burst < 0 {
		return fmt.Errorf("resolver.rate_limit.burst must be >= 0")
	}
	if c.Resolver.RateLimit.Enabled && c.Resolver.RateLimit.QPS == 0 {
		return fmt.Errorf("resolver.rate_limit.qps must be > 0 when rate limiting is enabled")
	}
	if c.Resolver.RateLimit.Enabled && c.Resolver.RateLimit.Burst == 0 {
		return fmt.Errorf("resolver.rate_limit.burst must be > 0 when rate limiting is enabled")
	}
	if (c.Dashboard.TLSCertFile == "") != (c.Dashboard.TLSKeyFile == "") {
		return fmt.Errorf("dashboard: tls_cert_file and tls_key_file must both be set or both be empty")
	}
	mode := strings.ToLower(c.Filtering.Mode)
	if mode != "blacklist" && mode != "whitelist" && mode != "off" {
		return fmt.Errorf("filtering.mode must be blacklist, whitelist, or off")
	}
	for _, r := range c.Records {
		if r.Name == "" || r.Value == "" {
			return fmt.Errorf("custom record missing name or value")
		}
		if strings.Contains(r.Name, "*") && !strings.HasPrefix(r.Name, "*.") {
			return fmt.Errorf("custom record %q: wildcard must be the leftmost label (e.g. *.home)", r.Name)
		}
	}
	return nil
}

func (c *Config) Addr() string {
	return fmt.Sprintf("%s:%d", c.Server.Listen, c.Server.Port)
}

func (c *Config) DashboardAddr() string {
	return fmt.Sprintf("%s:%d", c.Dashboard.Listen, c.Dashboard.Port)
}

func (c *Config) AuthEnabled() bool {
	return c.Dashboard.Auth.Username != "" && c.Dashboard.Auth.Password != ""
}

func (c *Config) Save() error {
	if c.path == "" {
		return fmt.Errorf("no config path set")
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return os.WriteFile(c.path, data, 0644)
}
