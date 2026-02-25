// Package protect provides ransomware protection capabilities.
package protect

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ProtectionStrategy represents a protection strategy.
type ProtectionStrategy string

const (
	StrategyBlocking    ProtectionStrategy = "blocking"
	StrategyQuarantine  ProtectionStrategy = "quarantine"
	StrategySnapshot    ProtectionStrategy = "snapshot"
	StrategyMonitoring  ProtectionStrategy = "monitoring"
	StrategyIsolation   ProtectionStrategy = "isolation"
)

// ProtectionRule represents a protection rule.
type ProtectionRule struct {
	ID            string
	Name          string
	Description   string
	Strategy      ProtectionStrategy
	Conditions    []string
	Actions       []string
	Enabled       bool
	Priority      int
	LastTriggered time.Time
}

// ProtectedFile represents a protected file.
type ProtectedFile struct {
	Path        string
	OriginalHash string
	SnapshotPath string
	ProtectedAt  time.Time
	Status       string // protected, quarantined, blocked
}

// ProtectionStatus represents protection status.
type ProtectionStatus struct {
	IsActive      bool
	Strategy      ProtectionStrategy
	RulesCount    int
	ProtectedFiles int
	ThreatsBlocked int
	LastUpdate    time.Time
}

// ProtectionEngine manages ransomware protection.
type ProtectionEngine struct {
	rules           []ProtectionRule
	protectedFiles  map[string]*ProtectedFile
	status          *ProtectionStatus
	handlers        []ProtectionHandler
	mu              sync.RWMutex
}

// ProtectionHandler handles protection events.
type ProtectionHandler func(event ProtectionEvent) error

// ProtectionEvent represents a protection event.
type ProtectionEvent struct {
	Type        string
	Timestamp   time.Time
	FilePath    string
	ThreatType  string
	Action      string
	Status      string
	Message     string
	Evidence    []string
}

// NewProtectionEngine creates a new protection engine.
func NewProtectionEngine() *ProtectionEngine {
	return &ProtectionEngine{
		rules:          make([]ProtectionRule, 0),
		protectedFiles: make(map[string]*ProtectedFile),
		status: &ProtectionStatus{
			IsActive:       false,
			Strategy:       StrategyMonitoring,
			RulesCount:     0,
			ProtectedFiles: 0,
			ThreatsBlocked: 0,
			LastUpdate:     time.Now(),
		},
	}
}

// AddRule adds a protection rule.
func (e *ProtectionEngine) AddRule(rule ProtectionRule) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.rules = append(e.rules, rule)
	e.status.RulesCount = len(e.rules)
	e.status.LastUpdate = time.Now()
}

// GetRules returns all rules.
func (e *ProtectionEngine) GetRules() []ProtectionRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.rules
}

// EnableRule enables a rule.
func (e *ProtectionEngine) EnableRule(ruleID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for i := range e.rules {
		if e.rules[i].ID == ruleID {
			e.rules[i].Enabled = true
			return nil
		}
	}
	return fmt.Errorf("rule not found: %s", ruleID)
}

// DisableRule disables a rule.
func (e *ProtectionEngine) DisableRule(ruleID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for i := range e.rules {
		if e.rules[i].ID == ruleID {
			e.rules[i].Enabled = false
			return nil
		}
	}
	return fmt.Errorf("rule not found: %s", ruleID)
}

// RegisterHandler registers a protection handler.
func (e *ProtectionEngine) RegisterHandler(handler ProtectionHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.handlers = append(e.handlers, handler)
}

// StartProtection starts protection.
func (e *ProtectionEngine) StartProtection(strategy ProtectionStrategy) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.status.IsActive = true
	e.status.Strategy = strategy
	e.status.LastUpdate = time.Now()

	return nil
}

// StopProtection stops protection.
func (e *ProtectionEngine) StopProtection() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.status.IsActive = false
	e.status.LastUpdate = time.Now()
}

// IsProtectionActive returns if protection is active.
func (e *ProtectionEngine) IsProtectionActive() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.status.IsActive
}

// GetStatus returns protection status.
func (e *ProtectionEngine) GetStatus() ProtectionStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return *e.status
}

// CheckFile checks if file should be protected.
func (e *ProtectionEngine) CheckFile(filePath string) (*ProtectionEvent, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Check all rules
	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}

		// Check if rule applies to this file
		if ruleAppliesTo(rule, filePath) {
			event := &ProtectionEvent{
				Type:        "file_check",
				Timestamp:   time.Now(),
				FilePath:    filePath,
				ThreatType:  rule.Name,
				Action:      rule.Actions[0],
				Status:      "blocked",
				Message:     fmt.Sprintf("Blocked by rule: %s", rule.Name),
				Evidence:    rule.Conditions,
			}

			// Trigger handlers
			for _, handler := range e.handlers {
				_ = handler(*event)
			}

			return event, nil
		}
	}

	return nil, nil
}

// ProtectFile protects a file.
func (e *ProtectionEngine) ProtectFile(filePath string, originalHash string) (*ProtectedFile, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Create snapshot
	snapshotPath := e.createSnapshot(filePath)

	// Create protected file entry
	protected := &ProtectedFile{
		Path:        filePath,
		OriginalHash: originalHash,
		SnapshotPath: snapshotPath,
		ProtectedAt:  time.Now(),
		Status:      "protected",
	}

	e.protectedFiles[filePath] = protected
	e.status.ProtectedFiles++
	e.status.LastUpdate = time.Now()

	return protected, nil
}

// createSnapshot creates a snapshot of a file.
func (e *ProtectionEngine) createSnapshot(filePath string) string {
	// In production: create cryptographic snapshot
	// For demo: return a path
	snapshotPath := filePath + ".snapshot" + fmt.Sprintf("%d", time.Now().UnixNano())

	// In production: copy file content with hash verification
	// data, _ := os.ReadFile(filePath)
	// os.WriteFile(snapshotPath, data, 0600)

	return snapshotPath
}

// BlockFile blocks a file from modification.
func (e *ProtectionEngine) BlockFile(filePath string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Create protection marker
	markerPath := filePath + ".protected"
	os.WriteFile(markerPath, []byte("protected"), 0600)

	// In production: set file attributes to prevent modification

	return nil
}

// QuarantineFile quarantines a suspicious file.
func (e *ProtectionEngine) QuarantineFile(filePath string, threatType string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Create quarantine directory
	quarantineDir := "/var/quarantine"
	os.MkdirAll(quarantineDir, 0755)

	// Move file to quarantine
	quarantinePath := filepath.Join(quarantineDir, fmt.Sprintf("%s_%s_%d", threatType, filepath.Base(filePath), time.Now().UnixNano()))
	os.Rename(filePath, quarantinePath)

	// Update protected file status
	if pf, ok := e.protectedFiles[filePath]; ok {
		pf.Status = "quarantined"
	}

	e.status.ThreatsBlocked++
	e.status.LastUpdate = time.Now()

	return nil
}

// RestoreFile restores a file from snapshot.
func (e *ProtectionEngine) RestoreFile(filePath string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	pf, ok := e.protectedFiles[filePath]
	if !ok {
		return fmt.Errorf("file not found in protected files: %s", filePath)
	}

	// Read snapshot
	snapshotData, err := os.ReadFile(pf.SnapshotPath)
	if err != nil {
		return fmt.Errorf("failed to read snapshot: %v", err)
	}

	// Restore file
	err = os.WriteFile(filePath, snapshotData, 0644)
	if err != nil {
		return fmt.Errorf("failed to restore file: %v", err)
	}

	pf.Status = "restored"
	e.status.LastUpdate = time.Now()

	return nil
}

// containsSubstring checks if string contains substring.
func containsSubstring(s, substr string) bool {
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ruleAppliesTo checks if rule applies to file.
func ruleAppliesTo(rule ProtectionRule, filePath string) bool {
	for _, condition := range rule.Conditions {
		if condition == "all_files" {
			return true
		}
		if containsSubstring(filePath, condition) {
			return true
		}
	}
	return false
}

// CreateCommonRules creates common protection rules.
func CreateCommonRules() []ProtectionRule {
	return []ProtectionRule{
		{
			ID:          "rule-001",
			Name:        "Block Encrypted Files",
			Description: "Block files being renamed with encrypted extensions",
			Strategy:    StrategyBlocking,
			Conditions:  []string{".locked", ".encrypted", ".enc", ".crypto"},
			Actions:     []string{"block", "quarantine"},
			Enabled:     true,
			Priority:    1,
		},
		{
			ID:          "rule-002",
			Name:        "Block Bulk File Modifications",
			Description: "Block processes modifying more than 100 files in 1 minute",
			Strategy:    StrategyMonitoring,
			Conditions:  []string{"bulk_modification"},
			Actions:     []string{"alert", "block"},
			Enabled:     true,
			Priority:    2,
		},
		{
			ID:          "rule-003",
			Name:        "Protect Sensitive Directories",
			Description: "Protect user data directories from modification",
			Strategy:    StrategySnapshot,
			Conditions:  []string{"/home", "/documents", "/data"},
			Actions:     []string{"snapshot", "monitor"},
			Enabled:     true,
			Priority:    3,
		},
		{
			ID:          "rule-004",
			Name:        "Block Suspicious Executables",
			Description: "Block execution of suspicious executables",
			Strategy:    StrategyBlocking,
			Conditions:  []string{".exe", ".bat", ".cmd", ".ps1"},
			Actions:     []string{"block", "scan"},
			Enabled:     true,
			Priority:    4,
		},
	}
}

// GenerateReport generates protection report.
func (e *ProtectionEngine) GenerateReport() string {
	status := e.GetStatus()

	var report string
	report += "=== Ransomware Protection Report ===\n\n"
	report += "Protection Status: "
	if status.IsActive {
		report += "ACTIVE (" + string(status.Strategy) + ")\n"
	} else {
		report += "INACTIVE\n"
	}
	report += "Rules Active: " + fmt.Sprintf("%d", status.RulesCount) + "\n"
	report += "Protected Files: " + fmt.Sprintf("%d", status.ProtectedFiles) + "\n"
	report += "Threats Blocked: " + fmt.Sprintf("%d", status.ThreatsBlocked) + "\n"
	report += "Last Update: " + status.LastUpdate.Format("2006-01-02 15:04:05") + "\n"

	return report
}

// GetProtectionEngine returns engine.
func GetProtectionEngine(engine *ProtectionEngine) *ProtectionEngine {
	return engine
}

// GetProtectedFile returns protected file.
func GetProtectedFile(pf *ProtectedFile) *ProtectedFile {
	return pf
}