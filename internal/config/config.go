// Package config handles loading and validating cert-monitor configuration.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds all configuration for cert-monitor.
type Config struct {
	// Targets is the list of host:port or host addresses to scan.
	Targets []string `yaml:"targets"`

	// CheckInterval is how often to re-scan in daemon mode (e.g., 1h, 30m).
	CheckInterval time.Duration `yaml:"check_interval"`

	// AlertDaysThreshold triggers a warning when cert expires within this many days.
	AlertDaysThreshold int `yaml:"alert_days_threshold"`

	// AlertPort is the local TCP port where a JSON status report is exposed.
	AlertPort int `yaml:"alert_port"`

	// AlertWebhook is an optional HTTP endpoint to POST JSON alerts to.
	AlertWebhook string `yaml:"alert_webhook"`

	// AlertWebhookHeaders are optional extra HTTP headers for the webhook.
	AlertWebhookHeaders map[string]string `yaml:"alert_webhook_headers"`

	// LogPath is the file path where scan events are logged (empty = stdout only).
	LogPath string `yaml:"log_path"`

	// StorePath is the directory where historical scan results are persisted.
	StorePath string `yaml:"store_path"`

	// JSONOutput switches output to machine-readable JSON format.
	JSONOutput bool `yaml:"json_output"`

	// WarnOnly downgrades critical-severity items to warning (no exit code 2).
	WarnOnly bool `yaml:"warn_only"`

	// DaemonMode runs the scanner on a repeating schedule.
	DaemonMode bool `yaml:"daemon_mode"`

	// Timeout is the per-host connection timeout.
	Timeout time.Duration `yaml:"timeout"`

	// InsecureSkipVerify bypasses certificate chain validation (not recommended).
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
}

// DefaultConfig returns a Config with sensible defaults pre-populated.
func DefaultConfig() *Config {
	return &Config{
		Targets:            []string{},
		CheckInterval:      1 * time.Hour,
		AlertDaysThreshold: 30,
		AlertPort:          8765,
		AlertWebhook:       "",
		AlertWebhookHeaders: nil,
		LogPath:            "",
		StorePath:          "./.cert-store",
		JSONOutput:         false,
		WarnOnly:           false,
		DaemonMode:         false,
		Timeout:            10 * time.Second,
		InsecureSkipVerify: false,
	}
}

// Load reads and parses a YAML configuration file, then returns the resulting Config.
// If the file does not exist, an error is returned.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}

	return cfg, nil
}

// Validate checks the config for logical errors and returns the first error found, if any.
func (c *Config) Validate() error {
	if len(c.Targets) == 0 {
		return fmt.Errorf("no targets configured (set targets: in YAML or --hosts on CLI)")
	}
	for _, t := range c.Targets {
		if strings.TrimSpace(t) == "" {
			return fmt.Errorf("empty target in list")
		}
	}
	if c.AlertDaysThreshold < 0 {
		return fmt.Errorf("alert_days_threshold must be >= 0, got %d", c.AlertDaysThreshold)
	}
	if c.AlertPort < 0 || c.AlertPort > 65535 {
		return fmt.Errorf("alert_port must be between 0 and 65535, got %d", c.AlertPort)
	}
	if c.CheckInterval < time.Second {
		return fmt.Errorf("check_interval must be at least 1 second, got %v", c.CheckInterval)
	}
	return nil
}