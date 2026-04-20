// Package main is the entry point for the cert-monitor CLI.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	version   = "1.0.0"
	buildDate = "2026-04-20"
)

// ─────────────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────────────

type config struct {
	targets              []string
	checkInterval        time.Duration
	alertDaysThreshold   int
	alertPort            int
	alertWebhook         string
	alertWebhookHeaders  map[string]string
	storePath            string
	jsonOutput           bool
	warnOnly             bool
	daemonMode           bool
	timeout              time.Duration
}

func loadConfig(f flagEnv) (*config, error) {
	cfg := &config{
		targets:            []string{"google.com", "github.com"},
		checkInterval:      1 * time.Hour,
		alertDaysThreshold: 30,
		alertPort:          8765,
		storePath:          "./.cert-store",
		timeout:            10 * time.Second,
	}

	// Try loading YAML config file (only fields we need).
	if data, err := os.ReadFile(f.configPath); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])

			switch key {
			case "targets":
				// Multi-line list: collect indent continuation lines.
				// Simple approach: scan subsequent lines until indent changes.
			case "check_interval":
				if d, err := time.ParseDuration(val); err == nil {
					cfg.checkInterval = d
				}
			case "alert_days_threshold":
				var n int
				if _, err := fmt.Sscan(val, &n); err == nil {
					cfg.alertDaysThreshold = n
				}
			case "alert_port":
				var n int
				if _, err := fmt.Sscan(val, &n); err == nil {
					cfg.alertPort = n
				}
			case "alert_webhook":
				cfg.alertWebhook = val
			case "store_path":
				cfg.storePath = val
			case "json_output":
				cfg.jsonOutput = val == "true"
			case "warn_only":
				cfg.warnOnly = val == "true"
			case "daemon_mode":
				cfg.daemonMode = val == "true"
			case "timeout":
				if d, err := time.ParseDuration(val); err == nil {
					cfg.timeout = d
				}
			}
		}
	}

	// Apply CLI overrides.
	if f.hosts != "" {
		cfg.targets = strings.Split(f.hosts, ",")
	}
	if f.checkInterval > 0 {
		cfg.checkInterval = f.checkInterval
	}
	if f.alertDays > 0 {
		cfg.alertDaysThreshold = f.alertDays
	}
	if f.alertPort > 0 {
		cfg.alertPort = f.alertPort
	}
	if f.jsonOutput {
		cfg.jsonOutput = true
	}
	if f.warnOnly {
		cfg.warnOnly = true
	}
	if f.daemonMode {
		cfg.daemonMode = true
	}

	if len(cfg.targets) == 0 {
		return nil, fmt.Errorf("no targets configured (set in YAML or --hosts)")
	}
	return cfg, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Alerter
// ─────────────────────────────────────────────────────────────────────────────

type alerter struct {
	cfg    *config
	server *http.Server
	mu     sync.RWMutex
	latest interface{}
}

func newAlerter(cfg *config) *alerter {
	a := &alerter{cfg: cfg}

	if cfg.alertPort > 0 {
		mux := http.NewServeMux()
		mux.HandleFunc("/health", a.healthHandler)
		mux.HandleFunc("/status", a.statusHandler)

		a.server = &http.Server{
			Addr:    fmt.Sprintf(":%d", cfg.alertPort),
			Handler: mux,
		}

		go func() {
			if err := a.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("[alerter] status server error: %v", err)
			}
		}()
	}

	return a
}

func (a *alerter) Alert(results interface{}) {
	a.mu.Lock()
	a.latest = results
	a.mu.Unlock()

	items, ok := results.([]map[string]interface{})
	if !ok {
		return
	}

	for _, m := range items {
		severity, _ := m["Severity"].(int)
		if severity == 0 {
			continue
		}

		host, _ := m["Host"].(string)
		subject, _ := m["Subject"].(string)
		days, _ := m["DaysRemaining"].(int)
		errMsg, _ := m["Error"].(string)

		label := "WARNING"
		if severity == 2 {
			label = "CRITICAL"
		}

		msg := fmt.Sprintf("[%s] %s — %s (%d days remaining)", label, host, subject, days)

		if severity == 2 {
			log.Printf("🔴 %s", msg)
		} else {
			log.Printf("⚠️  %s", msg)
		}

		if a.cfg.alertWebhook != "" {
			a.sendWebhook(label, host, subject, days, errMsg)
		}
	}
}

func (a *alerter) sendWebhook(severity, host, subject string, days int, errMsg string) {
	payload := map[string]interface{}{
		"alert":           "cert-expiry",
		"severity":        severity,
		"host":            host,
		"subject":         subject,
		"days_remaining":  days,
		"error":           errMsg,
		"timestamp":       time.Now().UTC().Format(time.RFC3339),
	}

	body, _ := json.Marshal(payload)

	req, err := http.NewRequest(http.MethodPost, a.cfg.alertWebhook, bytes.NewReader(body))
	if err != nil {
		log.Printf("[alerter] webhook build error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range a.cfg.alertWebhookHeaders {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[alerter] webhook delivery failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		log.Printf("[alerter] webhook returned HTTP %d", resp.StatusCode)
	}
}

func (a *alerter) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok","service":"cert-monitor"}`))
}

func (a *alerter) statusHandler(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	results := a.latest
	a.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	if results == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":"no scan results available yet"}`))
		return
	}

	data, err := json.Marshal(results)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Write(data)
}

func (a *alerter) Close() error {
	if a.server != nil {
		return a.server.Close()
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Scan Result
// ─────────────────────────────────────────────────────────────────────────────

type scanResult struct {
	Host          string
	Subject       string
	Issuer        string
	NotBefore     time.Time
	NotAfter      time.Time
	DaysRemaining int
	Severity      int // 0=OK, 1=Warning, 2=Critical
	Serial        string
	Fingerprint   string
	Error         string
}

const (
	sevOK       = 0
	sevWarning  = 1
	sevCritical = 2
)

func (r scanResult) statusLabel() string {
	switch r.Severity {
	case sevCritical:
		return "CRITICAL"
	case sevWarning:
		return "WARNING"
	default:
		return "OK"
	}
}

func (r scanResult) toMap() map[string]interface{} {
	return map[string]interface{}{
		"Host":          r.Host,
		"Subject":       r.Subject,
		"Issuer":        r.Issuer,
		"NotBefore":     r.NotBefore.Format(time.RFC3339),
		"NotAfter":      r.NotAfter.Format(time.RFC3339),
		"DaysRemaining": r.DaysRemaining,
		"Severity":      r.Severity,
		"Serial":        r.Serial,
		"Fingerprint":   r.Fingerprint,
		"Error":         r.Error,
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Scanning
// ─────────────────────────────────────────────────────────────────────────────

func scanAll(cfg *config) []scanResult {
	type res struct {
		result *scanResult
	}

	ch := make(chan *scanResult, len(cfg.targets))
	for _, target := range cfg.targets {
		go func(t string) {
			ch <- scanHost(t, cfg)
		}(target)
	}

	var results []scanResult
	for range cfg.targets {
		r := <-ch
		if r != nil {
			results = append(results, *r)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Severity != results[j].Severity {
			return results[i].Severity < results[j].Severity
		}
		return results[i].DaysRemaining < results[j].DaysRemaining
	})

	return results
}

func scanHost(hostport string, cfg *config) *scanResult {
	if !strings.Contains(hostport, ":") {
		hostport = net.JoinHostPort(hostport, "443")
	}

	res := &scanResult{Host: hostport}
	dialer := &net.Dialer{Timeout: cfg.timeout}

	tlsCfg := &tls.Config{ServerName: extractHost(hostport)}

	conn, err := tls.DialWithDialer(dialer, "tcp", hostport, tlsCfg)
	if err != nil {
		res.Severity = sevCritical
		res.Error = err.Error()
		return res
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		res.Severity = sevCritical
		res.Error = "no certificates returned"
		return res
	}

	cert := state.PeerCertificates[0]
	res.Subject = subjectToString(cert.Subject)
	res.Issuer = subjectToString(cert.Issuer)
	res.NotBefore = cert.NotBefore
	res.NotAfter = cert.NotAfter
	res.DaysRemaining = int(time.Until(cert.NotAfter).Hours() / 24)
	res.Serial = cert.SerialNumber.String()

	if sk := cert.SubjectKeyId; len(sk) > 0 && len(sk) >= 16 {
	 res.Fingerprint = fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:...%d bytes",
		sk[0], sk[1], sk[2], sk[3], sk[4], sk[5], sk[6], sk[7], len(sk))
	} else {
		res.Fingerprint = "unavailable"
	}

	if res.DaysRemaining <= 0 {
		res.Severity = sevCritical
	} else if res.DaysRemaining <= cfg.alertDaysThreshold {
		res.Severity = sevWarning
	} else {
		res.Severity = sevOK
	}

	if cfg.warnOnly && res.Severity == sevCritical {
		res.Severity = sevWarning
	}

	return res
}

func extractHost(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}

func subjectToString(name pkix.Name) string {
	var parts []string
	for _, rdn := range name.ToRDNSequence() {
		for _, atv := range rdn {
			if atv.Type.String() == "2.5.4.3" { // CN
				parts = append(parts, atv.Value.(string))
			}
		}
	}
	return strings.Join(parts, "; ")
}

// ─────────────────────────────────────────────────────────────────────────────
// Persistence
// ─────────────────────────────────────────────────────────────────────────────

func saveHistory(storePath string, results []scanResult) {
	_ = os.MkdirAll(storePath, 0755)

	maps := make([]map[string]interface{}, len(results))
	for i, r := range results {
		maps[i] = r.toMap()
	}

	data, _ := json.MarshalIndent(maps, "", "  ")
	filename := fmt.Sprintf("scan-%s.json", time.Now().Format("20060102-150405"))
	_ = os.WriteFile(storePath+"/"+filename, data, 0644)

	_ = os.Remove(storePath + "/latest.json")
	_ = os.Symlink(filename, storePath+"/latest.json")
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

func main() {
	flags := parseFlags()

	if flags.showVersion {
		fmt.Printf("cert-monitor %s (built %s)\n", version, buildDate)
		os.Exit(0)
	}

	cfg, err := loadConfig(flags)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	alerterInstance := newAlerter(cfg)

	if cfg.daemonMode {
		runDaemon(ctx, cfg, alerterInstance, sigChan)
	} else {
		runOnce(cfg, alerterInstance)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Run modes
// ─────────────────────────────────────────────────────────────────────────────

func runOnce(cfg *config, a *alerter) {
	fmt.Printf("cert-monitor v%s — scanning %d target(s)\n", version, len(cfg.targets))
	fmt.Println(strings.Repeat("─", 60))

	start := time.Now()
	results := scanAll(cfg)
	elapsed := time.Since(start)

	saveHistory(cfg.storePath, results)

	resultMaps := make([]map[string]interface{}, len(results))
	for i, r := range results {
		resultMaps[i] = r.toMap()
	}
	a.Alert(resultMaps)

	if cfg.jsonOutput {
		printJSON(resultMaps, elapsed)
	} else {
		printTable(results, elapsed)
	}

	for _, r := range results {
		if r.Severity <= sevWarning {
			os.Exit(1)
		}
	}
}

func runDaemon(ctx context.Context, cfg *config, a *alerter, sigChan <-chan os.Signal) {
	fmt.Printf("cert-monitor v%s — daemon mode (interval: %s)\n", version, cfg.checkInterval)
	fmt.Printf("Alert threshold: %d days | Status port: %d\n", cfg.alertDaysThreshold, cfg.alertPort)
	fmt.Println(strings.Repeat("─", 60))

	ticker := time.NewTicker(cfg.checkInterval)
	defer ticker.Stop()

	runDaemonScan(cfg, a)

	for {
		select {
		case <-ctx.Done():
			fmt.Println("\n[shutdown] stopping...")
			return
		case sig := <-sigChan:
			fmt.Printf("\n[%s] stopping...\n", sig)
			return
		case <-ticker.C:
			runDaemonScan(cfg, a)
		}
	}
}

func runDaemonScan(cfg *config, a *alerter) {
	fmt.Printf("\n[%s] running scan...\n", time.Now().Format("15:04:05"))
	results := scanAll(cfg)
	saveHistory(cfg.storePath, results)

	resultMaps := make([]map[string]interface{}, len(results))
	for i, r := range results {
		resultMaps[i] = r.toMap()
	}
	a.Alert(resultMaps)
}

// ─────────────────────────────────────────────────────────────────────────────
// Output
// ─────────────────────────────────────────────────────────────────────────────

func printTable(results []scanResult, elapsed time.Duration) {
	fmt.Printf("\n%-55s %-10s %s\n", "HOST", "STATUS", "EXPIRES IN")
	fmt.Println(strings.Repeat("─", 72))
	for _, r := range results {
		icon := "✅"
		if r.Severity == sevWarning {
			icon = "⚠️ "
		} else if r.Severity == sevCritical {
			icon = "🔴"
		}
		days := fmt.Sprintf("%d days", r.DaysRemaining)
		if r.DaysRemaining == 0 {
			days = "TODAY!"
		}
		subject := r.Subject
		if len(subject) > 52 {
			subject = subject[:49] + "..."
		}
		fmt.Printf("%s %-51s %-10s %s\n", icon, subject, r.statusLabel(), days)
	}
	fmt.Println(strings.Repeat("─", 72))
	fmt.Printf("%d certificate(s) scanned in %s\n", len(results), elapsed.Round(time.Millisecond))
}

func printJSON(results []map[string]interface{}, elapsed time.Duration) {
	fmt.Println("{")
	fmt.Printf("  \"version\": \"%s\",\n", version)
	fmt.Printf("  \"timestamp\": \"%s\",\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Printf("  \"duration_ms\": %d,\n", elapsed.Milliseconds())
	fmt.Printf("  \"targets\": %d,\n", len(results))
	fmt.Println("  \"results\": [")
	for i, m := range results {
		sep := ","
		if i == len(results)-1 {
			sep = ""
		}
		sev := m["Severity"].(int)
		label := "OK"
		if sev == 1 {
			label = "WARNING"
		} else if sev == 2 {
			label = "CRITICAL"
		}
		host := m["Host"].(string)
		subject := m["Subject"].(string)
		issuer := m["Issuer"].(string)
		days := m["DaysRemaining"].(int)
		notAfter := m["NotAfter"].(string)
		errMsg := ""
		if e, ok := m["Error"].(string); ok {
			errMsg = e
		}
		if errMsg != "" {
			fmt.Printf("    {\"host\":\"%s\",\"status\":\"ERROR\",\"error\":\"%s\"}%s\n", host, errMsg, sep)
		} else {
			fmt.Printf("    {\"host\":\"%s\",\"subject\":\"%s\",\"issuer\":\"%s\",\"days_remaining\":%d,\"status\":\"%s\",\"expires_at\":\"%s\"}%s\n",
				host, subject, issuer, days, label, notAfter, sep)
		}
	}
	fmt.Println("  ]")
	fmt.Println("}")
}