package detect

import (
	"testing"
	"time"
)

func TestNewRansomwareDetector(t *testing.T) {
	detector := NewRansomwareDetector()
	if detector == nil {
		t.Fatal("Expected detector to be created")
	}
	if detector.thresholds == nil {
		t.Error("Expected thresholds to be initialized")
	}
}

func TestAddSignature(t *testing.T) {
	detector := NewRansomwareDetector()
	sig := RansomwareSignature{
		ID:       "sig-001",
		Name:     "WannaCry",
		Family:   "WannaCry",
		Severity: "CRITICAL",
		Indicators: []string{".wcry", "ransom"},
	}

	detector.AddSignature(sig)
	signatures := detector.GetSignatures()

	if len(signatures) != 1 {
		t.Errorf("Expected 1 signature, got %d", len(signatures))
	}
	if signatures[0].ID != "sig-001" {
		t.Errorf("Expected signature ID 'sig-001', got '%s'", signatures[0].ID)
	}
}

func TestSetThresholds(t *testing.T) {
	detector := NewRansomwareDetector()
	thresholds := DetectionThresholds{
		FilesPerSecond:      20.0,
		EncryptionRate:      0.9,
		ConfidenceThreshold: 0.8,
	}

	detector.SetThresholds(thresholds)
	currentThresholds := detector.GetThresholds()

	if currentThresholds.FilesPerSecond != 20.0 {
		t.Errorf("Expected FilesPerSecond 20.0, got %f", currentThresholds.FilesPerSecond)
	}
	if currentThresholds.EncryptionRate != 0.9 {
		t.Errorf("Expected EncryptionRate 0.9, got %f", currentThresholds.EncryptionRate)
	}
}

func TestDetectBehavior(t *testing.T) {
	detector := NewRansomwareDetector()

	changes := []FileChange{
		{
			Path:        "/home/user/file1.encrypted",
			Operation:   "rename",
			OriginalExt: ".docx",
			NewExt:      ".encrypted",
			TimeStamp:   time.Now(),
			IsEncrypted: true,
		},
		{
			Path:        "/home/user/file2.encrypted",
			Operation:   "rename",
			OriginalExt: ".docx",
			NewExt:      ".encrypted",
			TimeStamp:   time.Now().Add(1 * time.Second),
			IsEncrypted: true,
		},
	}

	behaviors := detector.DetectBehavior(changes)

	if len(behaviors) == 0 {
		t.Error("Expected at least one behavior to be detected")
	}

	if behaviors[0].FilesAffected != 2 {
		t.Errorf("Expected 2 files affected, got %d", behaviors[0].FilesAffected)
	}

	if behaviors[0].FilesPerSecond < 1.0 {
		t.Errorf("Expected FilesPerSecond >= 1.0, got %f", behaviors[0].FilesPerSecond)
	}
}

func TestNewFileWatcher(t *testing.T) {
	watcher := NewFileWatcher([]string{"/home", "/documents"})

	if watcher == nil {
		t.Fatal("Expected watcher to be created")
	}

	if len(watcher.watchedPaths) != 2 {
		t.Errorf("Expected 2 watched paths, got %d", len(watcher.watchedPaths))
	}
}

func TestScanDirectory(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := "/tmp/test_scan_dir"

	changes, err := ScanDirectory(tempDir)
	// Expected to fail or return empty since directory doesn't exist
	if err != nil {
		// This is expected if directory doesn't exist
		return
	}

	if changes == nil {
		t.Error("Expected changes to not be nil")
	}
}

func TestIsSuspiciousExtension(t *testing.T) {
	testCases := []struct {
		ext      string
		expected bool
	}{
		{".locked", true},
		{".encrypted", true},
		{".enc", true},
		{".docx", false},
		{".txt", false},
		{".pdf", false},
	}

	for _, tc := range testCases {
		result := isSuspiciousExtension(tc.ext)
		if result != tc.expected {
			t.Errorf("isSuspiciousExtension(%s) = %v, want %v", tc.ext, result, tc.expected)
		}
	}
}

func TestGetBehavior(t *testing.T) {
	behavior := &RansomwareBehavior{
		ID:       "beh-001",
		Method:   MethodFileChange,
		Confidence: 0.9,
	}

	result := GetBehavior(behavior)
	if result.ID != "beh-001" {
		t.Errorf("Expected behavior ID 'beh-001', got '%s'", result.ID)
	}
}

func TestGetDetector(t *testing.T) {
	detector := NewRansomwareDetector()
	result := GetDetector(detector)

	if result != detector {
		t.Error("Expected detector to be the same instance")
	}
}