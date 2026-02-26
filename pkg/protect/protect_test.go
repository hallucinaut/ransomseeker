package protect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewProtectionEngine(t *testing.T) {
	e := NewProtectionEngine()
	if e == nil {
		t.Fatal("Expected engine to be created")
	}
	if e.rules == nil {
		t.Error("Expected rules map to be initialized")
	}
}

func TestAddRule(t *testing.T) {
	e := NewProtectionEngine()
	rule := ProtectionRule{
		ID:     "rule-1",
		Name:   "Test Rule",
	}

	e.AddRule(rule)
	rules := e.GetRules()

	if len(rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(rules))
	}
	if rules[0].ID != "rule-1" {
		t.Errorf("Expected rule ID 'rule-1', got '%s'", rules[0].ID)
	}
}

func TestEnableDisableRule(t *testing.T) {
	e := NewProtectionEngine()
	e.AddRule(ProtectionRule{ID: "rule-1", Enabled: false})

	err := e.EnableRule("rule-1")
	if err != nil {
		t.Errorf("Unexpected error enabling rule: %v", err)
	}

	rules := e.GetRules()
	if !rules[0].Enabled {
		t.Error("Expected rule to be enabled")
	}

	err = e.DisableRule("rule-1")
	if err != nil {
		t.Errorf("Unexpected error disabling rule: %v", err)
	}

	rules = e.GetRules()
	if rules[0].Enabled {
		t.Error("Expected rule to be disabled")
	}
}

func TestStartStopProtection(t *testing.T) {
	e := NewProtectionEngine()

	e.StartProtection("aggressive")
	if !e.IsProtectionActive() {
		t.Error("Expected protection to be active")
	}

	e.StopProtection()
	if e.IsProtectionActive() {
		t.Error("Expected protection to be inactive")
	}
}

func TestCheckFile(t *testing.T) {
	e := NewProtectionEngine()
	e.StartProtection("aggressive")

	// Add a rule that matches .xyz files
	e.AddRule(ProtectionRule{
		ID:         "rule-1",
		Enabled:    true,
		Conditions: []string{"extension:.xyz"},
	})

	// Add a rule that matches path substring
	e.AddRule(ProtectionRule{
		ID:         "rule-2",
		Enabled:    true,
		Conditions: []string{"path:/secure/"},
	})

	// Test extension rule
	_, err := e.CheckFile("/test/file.xyz")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Test path rule
	_, err = e.CheckFile("/secure/document.txt")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Test clean file
	event, err := e.CheckFile("/test/clean.txt")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if event != nil {
		t.Errorf("Expected nil event for clean file, got action: %s", event.Status)
	}
}

func TestCheckFile_Inactive(t *testing.T) {
	e := NewProtectionEngine()
	// Do not start protection
	e.AddRule(ProtectionRule{
		ID:         "rule-1",
		Enabled:    true,
		Conditions: []string{"extension:.xyz"},
	})

	event, err := e.CheckFile("/test/file.xyz")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if event != nil {
		t.Fatal("Expected no event when protection is inactive")
	}
}

func TestProtectAndRestoreFile(t *testing.T) {
	e := NewProtectionEngine()

	// Create test file
	dir := t.TempDir()
	filePath := filepath.Join(dir, "test.txt")
	os.WriteFile(filePath, []byte("original data"), 0644)

	// Protect file
	protected, err := e.ProtectFile(filePath, "testhash")
	if err != nil {
		t.Fatalf("ProtectFile failed: %v", err)
	}

	if protected.Status != "protected" {
		t.Errorf("Expected status 'protected', got '%s'", protected.Status)
	}

	// The mock createSnapshot creates a fake path
	if !strings.HasPrefix(protected.SnapshotPath, filePath+".snapshot") {
		t.Errorf("Expected snapshot path prefix %s, got %s", filePath+".snapshot", protected.SnapshotPath)
	}
	
	// Create the fake snapshot for restoration
	os.WriteFile(protected.SnapshotPath, []byte("snapshot data"), 0644)
	
	// Corrupt original file
	os.WriteFile(filePath, []byte("corrupted"), 0644)

	// Restore file
	err = e.RestoreFile(filePath)
	if err != nil {
		t.Fatalf("RestoreFile failed: %v", err)
	}

	// Check restored content
	restoredData, _ := os.ReadFile(filePath)
	if string(restoredData) != "snapshot data" {
		t.Errorf("Expected restored data 'snapshot data', got '%s'", string(restoredData))
	}
}

func TestQuarantineFile(t *testing.T) {
	e := NewProtectionEngine()

	dir := t.TempDir()
	filePath := filepath.Join(dir, "malicious.exe")
	os.WriteFile(filePath, []byte("bad stuff"), 0644)

	// Track the file first
	e.ProtectFile(filePath, "testhash")

	err := e.QuarantineFile(filePath, "ransomware")
	if err != nil {
		t.Fatalf("QuarantineFile failed: %v", err)
	}

	// Verify status updated
	if e.protectedFiles[filePath].Status != "quarantined" {
		t.Errorf("Expected status 'quarantined', got '%s'", e.protectedFiles[filePath].Status)
	}
}

func TestGenerateReport(t *testing.T) {
	e := NewProtectionEngine()
	e.AddRule(ProtectionRule{ID: "rule-1", Name: "Test Rule", Enabled: true})
	e.ProtectFile("/test/file.txt", "hash")

	report := e.GenerateReport()
	_ = report
}