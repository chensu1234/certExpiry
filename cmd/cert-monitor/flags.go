// Package main holds top-level flags and the main entry point.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// flagEnv collects all CLI flags as a struct with defaults applied after config loading.
type flagEnv struct {
	configPath    string
	hosts         string
	checkInterval time.Duration
	alertDays     int
	alertPort     int
	jsonOutput    bool
	warnOnly      bool
	showVersion   bool
	daemonMode    bool
}

var globalFlags flagEnv

func parseFlags() flagEnv {
	cfgPath := flag.String("config", "config/cert-monitor.yml", "Path to YAML configuration file")
	hosts := flag.String("hosts", "", "Comma-separated list of host:port targets (overrides config)")
	interval := flag.Duration("interval", 0, "Check interval in daemon mode (e.g., 1h30m)")
	alertDays := flag.Int("alert-days", 0, "Warn when certificate expires within N days")
	alertPort := flag.Int("alert-port", 0, "Local HTTP port for status/health endpoint")
	jsonOut := flag.Bool("json", false, "Output results as JSON")
	warnOnly := flag.Bool("warn-only", false, "Report critical issues as warnings (exit 0)")
	version := flag.Bool("version", false, "Print version and exit")
	daemon := flag.Bool("daemon", false, "Run continuously in the background")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "cert-monitor v%s — TLS/SSL certificate expiry monitor\n\n", "1.0.0")
		fmt.Fprintf(os.Stderr, "Usage:\n  cert-monitor [flags]\n\nFlags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  cert-monitor --hosts google.com,github.com\n")
		fmt.Fprintf(os.Stderr, "  cert-monitor --config /etc/cert-monitor.yml --daemon\n")
		fmt.Fprintf(os.Stderr, "  cert-monitor --hosts example.com:443 --alert-days 14 --json\n")
	}

	flag.Parse()

	return flagEnv{
		configPath:    *cfgPath,
		hosts:         *hosts,
		checkInterval: *interval,
		alertDays:     *alertDays,
		alertPort:     *alertPort,
		jsonOutput:    *jsonOut,
		warnOnly:      *warnOnly,
		showVersion:   *version,
		daemonMode:    *daemon,
	}
}

// sanitizeHosts is kept for future hostname validation logic.
// Currently hosts are accepted as-is and resolved at connection time.
func sanitizeHosts(raw string) []string {
	parts := strings.Split(raw, ",")
	var cleaned []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			cleaned = append(cleaned, p)
		}
	}
	return cleaned
}