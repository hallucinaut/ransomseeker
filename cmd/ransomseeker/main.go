package main

import (
	"fmt"
	"os"
	"time"

	"github.com/hallucinaut/ransomseeker/pkg/detect"
	"github.com/hallucinaut/ransomseeker/pkg/protect"
	"github.com/hallucinaut/ransomseeker/pkg/recovery"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	switch os.Args[1] {
	case "detect":
		detectRansomware()
	case "protect":
		protectFiles()
	case "recover":
		recoverFiles()
	case "scan":
		scanDirectory()
	case "report":
		generateReport()
	case "help", "--help", "-h":
		printUsage()
	case "version":
		fmt.Printf("ransomseeker version %s\n", version)
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
	}
}

func printUsage() {
	fmt.Printf(`ransomseeker - Ransomware Behavior Detection & Prevention

Usage:
  ransomseeker <command> [options]

Commands:
  detect      Detect ransomware behavior
  protect     Protect files from ransomware
  recover     Recover from ransomware attack
  scan        Scan directory for suspicious files
  report      Generate ransomseeker report
  help        Show this help message
  version     Show version information

Examples:
  ransomseeker detect
  ransomseeker protect /path/to/protect
  ransomseeker recover /path/to/recover
  ransomseeker scan /path/to/scan
`, "ransomseeker")
}

func detectRansomware() {
	fmt.Println("Ransomware Behavior Detection")
	fmt.Println("==============================")
	fmt.Println()

	detector := detect.NewRansomwareDetector()

	// Add known signatures
	signatures := []detect.RansomwareSignature{
		{
			ID:       "sig-001",
			Name:     "WannaCry",
			Family:   "WannaCry",
			Severity: "CRITICAL",
			Indicators: []string{".wcry", "ransom", "bitcoin"},
			BehaviorPatterns: []string{"bulk_encryption", "lateral_movement"},
		},
		{
			ID:       "sig-002",
			Name:     "Ryuk",
			Family:   "Ryuk",
			Severity: "CRITICAL",
			Indicators: []string{".ryuk", "ransomware", "bitcoin"},
			BehaviorPatterns: []string{"high_speed_encryption", "backup_deletion"},
		},
		{
			ID:       "sig-003",
			Name:     "LockBit",
			Family:   "LockBit",
			Severity: "CRITICAL",
			Indicators: []string{".lockbit", "ransom", "bitcoin"},
			BehaviorPatterns: []string{"bulk_encryption", "data_exfiltration"},
		},
	}

	for _, sig := range signatures {
		detector.AddSignature(sig)
	}

	// Create file watcher
	watcher := detect.NewFileWatcher([]string{"/home", "/documents", "/data"})
	watcher.OnChange(func(change detect.FileChange) {
		fmt.Printf("File change detected: %s\n", change.Path)
	})

	// Simulate file changes
	changes := []detect.FileChange{
		{
			Path:        "/home/user/document1.docx.locked",
			Operation:   "rename",
			OriginalExt: ".docx",
			NewExt:      ".locked",
			TimeStamp:   time.Now(),
			IsEncrypted: true,
		},
		{
			Path:        "/home/user/document2.docx.locked",
			Operation:   "rename",
			OriginalExt: ".docx",
			NewExt:      ".locked",
			TimeStamp:   time.Now().Add(1 * time.Second),
			IsEncrypted: true,
		},
		{
			Path:        "/home/user/document3.docx.locked",
			Operation:   "rename",
			OriginalExt: ".docx",
			NewExt:      ".locked",
			TimeStamp:   time.Now().Add(2 * time.Second),
			IsEncrypted: true,
		},
	}

	// Detect behavior
	behaviors := detector.DetectBehavior(changes)

	fmt.Println("Detection Results:")
	fmt.Println()

	for i, behavior := range behaviors {
		fmt.Printf("[%d] Behavior ID: %s\n", i+1, behavior.ID)
		fmt.Printf("    Method: %s\n", behavior.Method)
		fmt.Printf("    Confidence: %.1f%%\n", behavior.Confidence*100)
		fmt.Printf("    Threat Level: %s\n", behavior.ThreatLevel)
		fmt.Printf("    Files Affected: %d\n", behavior.FilesAffected)
		fmt.Printf("    Files/Second: %.1f\n", behavior.FilesPerSecond)
		fmt.Printf("    Encryption Rate: %.1f%%\n", behavior.EncryptionRate*100)
		fmt.Printf("    Is Malicious: %v\n", behavior.IsMalicious)

		if behavior.Signature != nil {
			fmt.Printf("    Signature Match: %s (%s)\n", behavior.Signature.Name, behavior.Signature.Family)
		}

		fmt.Println()
	}

	if len(behaviors) == 0 {
		fmt.Println("No ransomware behavior detected")
	}
}

func protectFiles() {
	fmt.Println("File Protection")
	fmt.Println("===============")
	fmt.Println()

	engine := protect.NewProtectionEngine()

	// Add common rules
	commonRules := protect.CreateCommonRules()
	for _, rule := range commonRules {
		engine.AddRule(rule)
	}

	// Start protection
	err := engine.StartProtection(protect.StrategyBlocking)
	if err != nil {
		fmt.Printf("Error starting protection: %v\n", err)
		return
	}

	fmt.Printf("Protection started with strategy: %s\n", engine.GetStatus().Strategy)
	fmt.Println()

	// Check files
	files := []string{
		"/home/user/document.docx",
		"/home/user/suspicious.exe",
		"/home/user/locked_file.encrypted",
	}

	fmt.Println("Checking files:")
	for _, file := range files {
		event, err := engine.CheckFile(file)
		if err != nil {
			fmt.Printf("  %s: Error - %v\n", file, err)
			continue
		}

		if event != nil {
			fmt.Printf("  %s: BLOCKED - %s\n", file, event.Message)
		} else {
			fmt.Printf("  %s: OK\n", file)
		}
	}

	fmt.Println()
	fmt.Println(engine.GenerateReport())
}

func recoverFiles() {
	fmt.Println("Ransomware Recovery")
	fmt.Println("===================")
	fmt.Println()

	engine := recovery.NewRecoveryEngine()

	// Add common plans
	commonPlans := recovery.CreateCommonPlans()
	for _, plan := range commonPlans {
		engine.AddPlan(plan)
	}

	fmt.Println("Available Recovery Plans:")
	for i, plan := range commonPlans {
		fmt.Printf("\n[%d] %s\n", i+1, plan.Name)
		fmt.Printf("    Method: %s\n", plan.Method)
		fmt.Printf("    Steps: %d\n", len(plan.Steps))
		fmt.Printf("    Success Rate: %.1f%%\n", plan.SuccessRate*100)
		fmt.Printf("    Estimated Time: %v\n", plan.EstimatedTime)
	}

	fmt.Println()

	// Execute a recovery plan
	fmt.Println("Executing Quick Recovery Plan...")
	result := engine.ExecutePlan("plan-001", []string{
		"/home/user/file1.encrypted",
		"/home/user/file2.encrypted",
		"/home/user/file3.encrypted",
	})

	fmt.Printf("\nRecovery Result:\n")
	fmt.Printf("  Status: %s\n", result.Status)
	fmt.Printf("  Files Recovered: %d/%d\n", result.FilesRecovered, result.TotalFiles)
	fmt.Printf("  Success Rate: %.1f%%\n", result.SuccessRate)
	fmt.Printf("  Duration: %v\n", result.Duration)

	fmt.Println()
	fmt.Println(engine.GenerateReport())
}

func scanDirectory() {
	fmt.Println("Directory Scan")
	fmt.Println("==============")
	fmt.Println()

	if len(os.Args) < 3 {
		fmt.Println("Usage: ransomseeker scan <directory>")
		return
	}

	dir := os.Args[2]

	// Scan directory
	changes, err := detect.ScanDirectory(dir)
	if err != nil {
		fmt.Printf("Error scanning directory: %v\n", err)
		return
	}

	fmt.Printf("Scanning directory: %s\n", dir)
	fmt.Printf("Total files checked: %d\n\n", len(changes))

	if len(changes) == 0 {
		fmt.Println("No suspicious files found")
		return
	}

	fmt.Println("Suspicious files found:")
	for i, change := range changes {
		fmt.Printf("\n[%d] %s\n", i+1, change.Path)
		fmt.Printf("    Extension: %s\n", change.OriginalExt)
		fmt.Printf("    Size: %d bytes\n", change.Size)
		fmt.Printf("    Time: %s\n", change.TimeStamp.Format("2006-01-02 15:04:05"))
	}
}

func generateReport() {
	fmt.Println("=== RansomSeeker Report ===")
	fmt.Println()

	// Detection report
	detector := detect.NewRansomwareDetector()
	signatures := []detect.RansomwareSignature{
		{ID: "sig-001", Name: "WannaCry", Family: "WannaCry", Severity: "CRITICAL"},
	}
	for _, sig := range signatures {
		detector.AddSignature(sig)
	}
	fmt.Println("Detection Engine:")
	fmt.Printf("  Signatures: %d\n", len(detector.GetSignatures()))
	fmt.Printf("  Thresholds: Files/Sec=%.1f, EncRate=%.1f%%\n",
		detector.GetThresholds().FilesPerSecond,
		detector.GetThresholds().EncryptionRate*100)
	fmt.Println()

	// Protection report
	protectEngine := protect.NewProtectionEngine()
	rules := protect.CreateCommonRules()
	for _, rule := range rules {
		protectEngine.AddRule(rule)
	}
	fmt.Println("Protection Engine:")
	fmt.Printf("  Rules: %d\n", protectEngine.GetStatus().RulesCount)
	fmt.Printf("  Status: %v\n", protectEngine.GetStatus().IsActive)
	fmt.Println()

	// Recovery report
	recoveryEngine := recovery.NewRecoveryEngine()
	plans := recovery.CreateCommonPlans()
	for _, plan := range plans {
		recoveryEngine.AddPlan(plan)
	}
	fmt.Println("Recovery Engine:")
	fmt.Printf("  Plans: %d\n", len(recoveryEngine.GetPlans()))
	fmt.Println()

	fmt.Println(recoveryEngine.GenerateReport())
}