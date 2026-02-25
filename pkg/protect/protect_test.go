package protect

import (
	"testing"
	"time"
)

func TestNewProtectionEngine(t *testing.T) {
	engine := NewProtectionEngine()
	if engine == nil {
		t.Fatal("Expected engine to be created")
	}
	if engine.status == nil {
		t.Error("Expected status to be initialized")
	}
}

func TestAddRule(t *testing.T) {
	engine := NewProtectionEngine()
	rule := ProtectionRule{
		ID:          "rule-001",
		Name:        "Block Encrypted Files",
		Description: "Block encrypted files",
		Strategy:    StrategyBlocking,
		Conditions:  []string{".encrypted"},
		Actions:     []string{"block"},
		Enabled:     true,
	}

	engine.AddRule(rule)
	rules := engine.GetRules()

	if len(rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(rules))
	}
	if rules[0].ID != "rule-001" {
		t.Errorf("Expected rule ID 'rule-001', got '%s'", rules[0].ID)
	}
}

func TestEnableRule(t *testing.T) {
	engine := NewProtectionEngine()
	rule := ProtectionRule{
		ID:       "rule-001",
		Name:     "Test Rule",
		Enabled:  false,
	}

	engine.AddRule(rule)
	err := engine.EnableRule("rule-001")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	rules := engine.GetRules()
	if !rules[0].Enabled {
		t.Error("Expected rule to be enabled")
	}
}

func TestDisableRule(t *testing.T) {
	engine := NewProtectionEngine()
	rule := ProtectionRule{
		ID:       "rule-001",
		Name:     "Test Rule",
		Enabled:  true,
	}

	engine.AddRule(rule)
	err := engine.DisableRule("rule-001")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	rules := engine.GetRules()
	if rules[0].Enabled {
		t.Error("Expected rule to be disabled")
	}
}

func TestStartProtection(t *testing.T) {
	engine := NewProtectionEngine()
	err := engine.StartProtection(StrategyBlocking)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	status := engine.GetStatus()
	if !status.IsActive {
		t.Error("Expected protection to be active")
	}
	if status.Strategy != StrategyBlocking {
		t.Errorf("Expected strategy 'blocking', got '%s'", status.Strategy)
	}
}

func TestIsProtectionActive(t *testing.T) {
	engine := NewProtectionEngine()

	if engine.IsProtectionActive() {
		t.Error("Expected protection to be inactive initially")
	}

	engine.StartProtection(StrategyMonitoring)
	if !engine.IsProtectionActive() {
		t.Error("Expected protection to be active after starting")
	}
}

func TestGetStatus(t *testing.T) {
	engine := NewProtectionEngine()
	status := engine.GetStatus()

	if status.RulesCount != 0 {
		t.Errorf("Expected 0 rules, got %d", status.RulesCount)
	}
}

func TestCreateCommonRules(t *testing.T) {
	rules := CreateCommonRules()

	if len(rules) == 0 {
		t.Error("Expected at least one rule")
	}

	// Check that rules have required fields
	for i, rule := range rules {
		if rule.ID == "" {
			t.Errorf("Rule %d has empty ID", i)
		}
		if rule.Name == "" {
			t.Errorf("Rule %d has empty name", i)
		}
	}
}

func TestGenerateReport(t *testing.T) {
	engine := NewProtectionEngine()
	engine.AddRule(ProtectionRule{
		ID:        "rule-001",
		Name:      "Test Rule",
		Enabled:   true,
		Priority:  1,
	})

	report := engine.GenerateReport()

	if report == "" {
		t.Error("Expected report to not be empty")
	}
	if len(report) < 50 {
		t.Errorf("Expected report to be at least 50 characters, got %d", len(report))
	}
}

func TestGetProtectionEngine(t *testing.T) {
	engine := NewProtectionEngine()
	result := GetProtectionEngine(engine)

	if result != engine {
		t.Error("Expected engine to be the same instance")
	}
}

func TestGetProtectedFile(t *testing.T) {
	pf := &ProtectedFile{
		Path:      "/path/to/file",
		Status:    "protected",
		ProtectedAt: time.Now(),
	}

	result := GetProtectedFile(pf)
	if result.Path != "/path/to/file" {
		t.Errorf("Expected path '/path/to/file', got '%s'", result.Path)
	}
}