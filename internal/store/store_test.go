package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewFileStore(t *testing.T) {
	tmp := t.TempDir()
	fs := NewFileStore(tmp)

	if _, err := os.Stat(tmp); os.IsNotExist(err) {
		t.Error("expected directory to be created")
	}

	fs.SaveHistory([]map[string]interface{}{
		{"host": "test.example.com", "days_remaining": 30, "severity": 0},
	})
}

func TestSaveHistoryCreatesFile(t *testing.T) {
	tmp := t.TempDir()
	fs := NewFileStore(tmp)

	results := []map[string]interface{}{
		{"host": "google.com", "days_remaining": 60, "severity": 0},
		{"host": "expired.example.com", "days_remaining": -5, "severity": 2},
	}
	fs.SaveHistory(results)

	latest := filepath.Join(tmp, "latest.json")
	if _, err := os.Stat(latest); os.IsNotExist(err) {
		t.Error("expected latest.json to be created")
	}
}

func TestLoadLatest(t *testing.T) {
	tmp := t.TempDir()
	fs := NewFileStore(tmp)

	_, err := fs.LoadLatest()
	if err == nil {
		t.Error("expected error when loading before any save")
	}

	fs.SaveHistory([]map[string]interface{}{
		{"host": "github.com", "days_remaining": 90},
	})

	latest, err := fs.LoadLatest()
	if err != nil {
		t.Errorf("unexpected error loading latest: %v", err)
	}
	if len(latest) == 0 {
		t.Error("expected at least one entry in latest scan")
	}
}

func TestHistory(t *testing.T) {
	tmp := t.TempDir()
	fs := NewFileStore(tmp)

	history, err := fs.History(10)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(history) != 0 {
		t.Errorf("expected empty history, got %d entries", len(history))
	}

	fs.SaveHistory([]map[string]interface{}{{"host": "test.com"}})
	fs.SaveHistory([]map[string]interface{}{{"host": "test.com"}})

	history, err = fs.History(10)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(history) < 1 {
		t.Error("expected at least 1 history entry after saves")
	}
}