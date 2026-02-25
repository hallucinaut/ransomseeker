package recovery

import (
	"testing"
	"time"
)

func TestNewRecoveryEngine(t *testing.T) {
	engine := NewRecoveryEngine()
	if engine == nil {
		t.Fatal("Expected engine to be created")
	}
	if engine.plans == nil {
		t.Error("Expected plans to be initialized")
	}
}

func TestAddPlan(t *testing.T) {
	engine := NewRecoveryEngine()
	plan := RecoveryPlan{
		ID:        "plan-001",
		Name:      "Quick Recovery",
		Method:    MethodSnapshot,
		Priority:  1,
		Steps:     make([]RecoveryStep, 0),
	}

	engine.AddPlan(plan)
	plans := engine.GetPlans()

	if len(plans) != 1 {
		t.Errorf("Expected 1 plan, got %d", len(plans))
	}
	if plans[0].ID != "plan-001" {
		t.Errorf("Expected plan ID 'plan-001', got '%s'", plans[0].ID)
	}
}

func TestGetPlan(t *testing.T) {
	engine := NewRecoveryEngine()
	plan := RecoveryPlan{
		ID:   "plan-001",
		Name: "Test Plan",
	}

	engine.AddPlan(plan)
	retrievedPlan := engine.GetPlan("plan-001")

	if retrievedPlan == nil {
		t.Error("Expected plan to be found")
	}
	if retrievedPlan.Name != "Test Plan" {
		t.Errorf("Expected plan name 'Test Plan', got '%s'", retrievedPlan.Name)
	}
}

func TestCreateRecoveryPlan(t *testing.T) {
	engine := NewRecoveryEngine()
	plan := engine.CreateRecoveryPlan("Test Plan", "snapshot")

	if plan == nil {
		t.Fatal("Expected plan to be created")
	}
	if plan.Name != "Test Plan" {
		t.Errorf("Expected plan name 'Test Plan', got '%s'", plan.Name)
	}
	if plan.Method != MethodSnapshot {
		t.Errorf("Expected method 'snapshot', got '%s'", plan.Method)
	}
}

func TestAddStep(t *testing.T) {
	engine := NewRecoveryEngine()
	plan := RecoveryPlan{
		ID:   "plan-001",
		Name: "Test Plan",
	}
	engine.AddPlan(plan)

	step := RecoveryStep{
		Order:         1,
		Name:          "Step 1",
		Description:   "First step",
		Timeout:       30 * time.Second,
		RetryCount:    3,
	}

	err := engine.AddStep("plan-001", step)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	plans := engine.GetPlans()
	if len(plans[0].Steps) != 1 {
		t.Errorf("Expected 1 step, got %d", len(plans[0].Steps))
	}
}

func TestExecutePlan(t *testing.T) {
	engine := NewRecoveryEngine()
	plan := RecoveryPlan{
		ID:   "plan-001",
		Name: "Test Plan",
	}
	engine.AddPlan(plan)

	result := engine.ExecutePlan("plan-001", []string{"/path/to/file1", "/path/to/file2"})

	if result == nil {
		t.Fatal("Expected result to be created")
	}
	if result.Status != "completed" {
		t.Errorf("Expected status 'completed', got '%s'", result.Status)
	}
	if result.TotalFiles != 2 {
		t.Errorf("Expected 2 files, got %d", result.TotalFiles)
	}
}

func TestCreateCommonPlans(t *testing.T) {
	plans := CreateCommonPlans()

	if len(plans) == 0 {
		t.Error("Expected at least one plan")
	}

	// Check that plans have required fields
	for i, plan := range plans {
		if plan.ID == "" {
			t.Errorf("Plan %d has empty ID", i)
		}
		if plan.Name == "" {
			t.Errorf("Plan %d has empty name", i)
		}
	}
}

func TestGenerateReport(t *testing.T) {
	engine := NewRecoveryEngine()
	engine.AddPlan(RecoveryPlan{
		ID:          "plan-001",
		Name:        "Quick Recovery",
		Method:      MethodSnapshot,
		Priority:    1,
		SuccessRate: 0.95,
	})

	report := engine.GenerateReport()

	if report == "" {
		t.Error("Expected report to not be empty")
	}
	if len(report) < 50 {
		t.Errorf("Expected report to be at least 50 characters, got %d", len(report))
	}
}

func TestGetRecoveryEngine(t *testing.T) {
	engine := NewRecoveryEngine()
	result := GetRecoveryEngine(engine)

	if result != engine {
		t.Error("Expected engine to be the same instance")
	}
}

func TestGetRecoveryPlan(t *testing.T) {
	plan := &RecoveryPlan{
		ID:   "plan-001",
		Name: "Test Plan",
	}

	result := GetRecoveryPlan(plan)
	if result.ID != "plan-001" {
		t.Errorf("Expected plan ID 'plan-001', got '%s'", result.ID)
	}
}

func TestGetRecoveryResult(t *testing.T) {
	result := &RecoveryResult{
		PlanID:   "plan-001",
		Status:   "completed",
		FilesRecovered: 10,
		TotalFiles:   10,
	}

	result2 := GetRecoveryResult(result)
	if result2.Status != "completed" {
		t.Errorf("Expected status 'completed', got '%s'", result2.Status)
	}
}