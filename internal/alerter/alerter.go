// Package alerter handles notification dispatch for certificate alerts.
package alerter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"cert-monitor/internal/config"
)

// Alerter dispatches notifications for certificate alerts to log, webhook, and an HTTP status endpoint.
type Alerter struct {
	cfg    *config.Config
	server *http.Server
	mu     sync.RWMutex
	// latestResults holds the most recent scan results for the /status endpoint.
	latestResults interface{}
}

// NewAlerter creates a new Alerter configured from cfg.
// It starts the internal HTTP status server if alert_port is non-zero.
func NewAlerter(cfg *config.Config) *Alerter {
	a := &Alerter{cfg: cfg}

	if cfg.AlertPort > 0 {
		mux := http.NewServeMux()
		mux.HandleFunc("/health", a.healthHandler)
		mux.HandleFunc("/status", a.statusHandler)

		a.server = &http.Server{
			Addr:    fmt.Sprintf(":%d", cfg.AlertPort),
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

// Alert dispatches notifications for all non-OK scan results.
// results is expected to be a []map[string]interface{}, typically in the form:
//   []map[string]interface{}{
//       {"Host": "...", "Subject": "...", "Severity": 1, "DaysRemaining": 10, "Error": ""},
//   }
func (a *Alerter) Alert(results interface{}) {
	a.mu.Lock()
	a.latestResults = results
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

		if a.cfg.AlertWebhook != "" {
			a.sendWebhook(label, host, subject, days, errMsg)
		}
	}
}

// sendWebhook POSTs a JSON payload to the configured webhook URL.
func (a *Alerter) sendWebhook(severity, host, subject string, days int, errMsg string) {
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

	req, err := http.NewRequest(http.MethodPost, a.cfg.AlertWebhook, bytes.NewReader(body))
	if err != nil {
		log.Printf("[alerter] webhook build error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range a.cfg.AlertWebhookHeaders {
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

// healthHandler returns a simple JSON health check response.
func (a *Alerter) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok","service":"cert-monitor"}`))
}

// statusHandler serves the latest scan results as JSON.
func (a *Alerter) statusHandler(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	results := a.latestResults
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

// Close shuts down the internal HTTP status server gracefully.
func (a *Alerter) Close() error {
	if a.server != nil {
		return a.server.Close()
	}
	return nil
}