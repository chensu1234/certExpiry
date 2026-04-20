package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.AlertDaysThreshold != 30 {
		t.Errorf("expected AlertDaysThreshold=30, got %d", cfg.AlertDaysThreshold)
	}
	if cfg.AlertPort != 8765 {
		t.Errorf("expected AlertPort=8765, got %d", cfg.AlertPort)
	}
	if cfg.CheckInterval != 3600000000000 {
		t.Errorf("expected CheckInterval=1h, got %v", cfg.CheckInterval)
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid config with targets",
			cfg: Config{
				Targets:            []string{"google.com:443", "github.com"},
				AlertDaysThreshold: 30,
				AlertPort:         8765,
				CheckInterval:     3600 * 1e9,
			},
			wantErr: false,
		},
		{
			name: "no targets",
			cfg: Config{
				Targets:            []string{},
				AlertDaysThreshold: 30,
				AlertPort:         8765,
				CheckInterval:     3600 * 1e9,
			},
			wantErr: true,
		},
		{
			name: "negative alert threshold",
			cfg: Config{
				Targets:            []string{"google.com"},
				AlertDaysThreshold: -5,
				AlertPort:         8765,
				CheckInterval:     3600 * 1e9,
			},
			wantErr: true,
		},
		{
			name: "invalid alert port",
			cfg: Config{
				Targets:            []string{"google.com"},
				AlertDaysThreshold: 30,
				AlertPort:         99999,
				CheckInterval:     3600 * 1e9,
			},
			wantErr: true,
		},
		{
			name: "check interval too short",
			cfg: Config{
				Targets:            []string{"google.com"},
				AlertDaysThreshold: 30,
				AlertPort:         8765,
				CheckInterval:     500000000, // 0.5s
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "cert-monitor-test.yml")

	content := `
targets:
  - test.example.com
  - another.example.com:443
check_interval: 30m
alert_days_threshold: 14
alert_port: 9000
json_output: true
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}

	if len(cfg.Targets) != 2 {
		t.Errorf("expected 2 targets, got %d", len(cfg.Targets))
	}
	if cfg.AlertDaysThreshold != 14 {
		t.Errorf("expected alert_days_threshold=14, got %d", cfg.AlertDaysThreshold)
	}
	if cfg.AlertPort != 9000 {
		t.Errorf("expected alert_port=9000, got %d", cfg.AlertPort)
	}
	if !cfg.JSONOutput {
		t.Error("expected json_output=true")
	}
}

func TestLoadConfigNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yml")
	if err == nil {
		t.Error("expected error for nonexistent file, got nil")
	}
}