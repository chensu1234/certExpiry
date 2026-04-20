// Package store provides persistence for cert-monitor scan history.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// FileStore persists scan results to a directory on disk as JSON files,
// one per scan run, with a latest.json symlink for easy access.
type FileStore struct {
	baseDir string
}

// ScanEntry represents a single certificate scan result in the store.
type ScanEntry struct {
	Timestamp   string `json:"timestamp"`
	Host        string `json:"host"`
	Subject     string `json:"subject"`
	Issuer      string `json:"issuer"`
	DaysLeft    int    `json:"days_remaining"`
	Severity    int    `json:"severity"`
	Fingerprint string `json:"fingerprint"`
	Error       string `json:"error,omitempty"`
}

// NewFileStore creates a FileStore that writes to the given directory.
// The directory is created if it does not exist.
func NewFileStore(baseDir string) *FileStore {
	_ = os.MkdirAll(baseDir, 0755)
	return &FileStore{baseDir: baseDir}
}

// SaveHistory writes a JSON snapshot of the latest scan results and maintains
// a "latest.json" symlink pointing to the most recent snapshot file.
func (s *FileStore) SaveHistory(results interface{}) {
	// Write a timestamped snapshot file.
	filename := fmt.Sprintf("scan-%s.json", time.Now().Format("20060102-150405"))
	path := filepath.Join(s.baseDir, filename)

	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		fmt.Printf("[store] failed to write %s: %v\n", path, err)
	}

	// Update the "latest" symlink.
	latestPath := filepath.Join(s.baseDir, "latest.json")
	_ = os.Remove(latestPath)
	_ = os.Symlink(filename, latestPath)
}

// LoadLatest reads and returns the most recent scan snapshot, or nil if unavailable.
func (s *FileStore) LoadLatest() ([]map[string]interface{}, error) {
	latestPath := filepath.Join(s.baseDir, "latest.json")
	data, err := os.ReadFile(latestPath)
	if err != nil {
		return nil, fmt.Errorf("no latest scan available: %w", err)
	}

	var results []map[string]interface{}
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("parse latest scan: %w", err)
	}
	return results, nil
}

// History returns all scan snapshot files ordered newest-first.
func (s *FileStore) History(limit int) ([]string, error) {
	entries, err := os.ReadDir(s.baseDir)
	if err != nil {
		return nil, err
	}

	var scanFiles []string
	for _, e := range entries {
		if name := e.Name(); len(name) > 5 && name[:5] == "scan-" {
			scanFiles = append(scanFiles, name)
		}
	}

	if len(scanFiles) > limit {
		return scanFiles[:limit], nil
	}
	return scanFiles, nil
}