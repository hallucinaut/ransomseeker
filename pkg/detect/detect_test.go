package detect

import (
	"reflect"
	"sync"
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
		ID:         "sig-001",
		Name:       "WannaCry",
		Family:     "WannaCry",
		Severity:   "CRITICAL",
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
		ID:         "beh-001",
		Method:     MethodFileChange,
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

func TestRansomwareDetector_AddSignature(t *testing.T) {
	type fields struct {
		signatures  []RansomwareSignature
		behaviors   []RansomwareBehavior
		fileWatcher *FileWatcher
		thresholds  *DetectionThresholds
		handlers    []BehaviorHandler
		mu          sync.RWMutex
	}
	type args struct {
		sig RansomwareSignature
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &RansomwareDetector{
				signatures:  tt.fields.signatures,
				behaviors:   tt.fields.behaviors,
				fileWatcher: tt.fields.fileWatcher,
				thresholds:  tt.fields.thresholds,
				handlers:    tt.fields.handlers,
				mu:          tt.fields.mu,
			}
			d.AddSignature(tt.args.sig)
		})
	}
}

func TestRansomwareDetector_GetSignatures(t *testing.T) {
	type fields struct {
		signatures  []RansomwareSignature
		behaviors   []RansomwareBehavior
		fileWatcher *FileWatcher
		thresholds  *DetectionThresholds
		handlers    []BehaviorHandler
		mu          sync.RWMutex
	}
	tests := []struct {
		name   string
		fields fields
		want   []RansomwareSignature
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &RansomwareDetector{
				signatures:  tt.fields.signatures,
				behaviors:   tt.fields.behaviors,
				fileWatcher: tt.fields.fileWatcher,
				thresholds:  tt.fields.thresholds,
				handlers:    tt.fields.handlers,
				mu:          tt.fields.mu,
			}
			if got := d.GetSignatures(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RansomwareDetector.GetSignatures() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRansomwareDetector_SetThresholds(t *testing.T) {
	type fields struct {
		signatures  []RansomwareSignature
		behaviors   []RansomwareBehavior
		fileWatcher *FileWatcher
		thresholds  *DetectionThresholds
		handlers    []BehaviorHandler
		mu          sync.RWMutex
	}
	type args struct {
		thresholds DetectionThresholds
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &RansomwareDetector{
				signatures:  tt.fields.signatures,
				behaviors:   tt.fields.behaviors,
				fileWatcher: tt.fields.fileWatcher,
				thresholds:  tt.fields.thresholds,
				handlers:    tt.fields.handlers,
				mu:          tt.fields.mu,
			}
			d.SetThresholds(tt.args.thresholds)
		})
	}
}

func TestRansomwareDetector_GetThresholds(t *testing.T) {
	type fields struct {
		signatures  []RansomwareSignature
		behaviors   []RansomwareBehavior
		fileWatcher *FileWatcher
		thresholds  *DetectionThresholds
		handlers    []BehaviorHandler
		mu          sync.RWMutex
	}
	tests := []struct {
		name   string
		fields fields
		want   DetectionThresholds
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &RansomwareDetector{
				signatures:  tt.fields.signatures,
				behaviors:   tt.fields.behaviors,
				fileWatcher: tt.fields.fileWatcher,
				thresholds:  tt.fields.thresholds,
				handlers:    tt.fields.handlers,
				mu:          tt.fields.mu,
			}
			if got := d.GetThresholds(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RansomwareDetector.GetThresholds() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRansomwareDetector_RegisterHandler(t *testing.T) {
	type fields struct {
		signatures  []RansomwareSignature
		behaviors   []RansomwareBehavior
		fileWatcher *FileWatcher
		thresholds  *DetectionThresholds
		handlers    []BehaviorHandler
		mu          sync.RWMutex
	}
	type args struct {
		handler BehaviorHandler
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &RansomwareDetector{
				signatures:  tt.fields.signatures,
				behaviors:   tt.fields.behaviors,
				fileWatcher: tt.fields.fileWatcher,
				thresholds:  tt.fields.thresholds,
				handlers:    tt.fields.handlers,
				mu:          tt.fields.mu,
			}
			d.RegisterHandler(tt.args.handler)
		})
	}
}

func TestRansomwareDetector_DetectBehavior(t *testing.T) {
	type fields struct {
		signatures  []RansomwareSignature
		behaviors   []RansomwareBehavior
		fileWatcher *FileWatcher
		thresholds  *DetectionThresholds
		handlers    []BehaviorHandler
		mu          sync.RWMutex
	}
	type args struct {
		changes []FileChange
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []*RansomwareBehavior
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &RansomwareDetector{
				signatures:  tt.fields.signatures,
				behaviors:   tt.fields.behaviors,
				fileWatcher: tt.fields.fileWatcher,
				thresholds:  tt.fields.thresholds,
				handlers:    tt.fields.handlers,
				mu:          tt.fields.mu,
			}
			if got := d.DetectBehavior(tt.args.changes); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RansomwareDetector.DetectBehavior() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRansomwareDetector_calculateConfidence(t *testing.T) {
	type fields struct {
		signatures  []RansomwareSignature
		behaviors   []RansomwareBehavior
		fileWatcher *FileWatcher
		thresholds  *DetectionThresholds
		handlers    []BehaviorHandler
		mu          sync.RWMutex
	}
	type args struct {
		behavior *RansomwareBehavior
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   float64
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &RansomwareDetector{
				signatures:  tt.fields.signatures,
				behaviors:   tt.fields.behaviors,
				fileWatcher: tt.fields.fileWatcher,
				thresholds:  tt.fields.thresholds,
				handlers:    tt.fields.handlers,
				mu:          tt.fields.mu,
			}
			if got := d.calculateConfidence(tt.args.behavior); got != tt.want {
				t.Errorf("RansomwareDetector.calculateConfidence() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRansomwareDetector_determineThreatLevel(t *testing.T) {
	type fields struct {
		signatures  []RansomwareSignature
		behaviors   []RansomwareBehavior
		fileWatcher *FileWatcher
		thresholds  *DetectionThresholds
		handlers    []BehaviorHandler
		mu          sync.RWMutex
	}
	type args struct {
		behavior *RansomwareBehavior
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &RansomwareDetector{
				signatures:  tt.fields.signatures,
				behaviors:   tt.fields.behaviors,
				fileWatcher: tt.fields.fileWatcher,
				thresholds:  tt.fields.thresholds,
				handlers:    tt.fields.handlers,
				mu:          tt.fields.mu,
			}
			if got := d.determineThreatLevel(tt.args.behavior); got != tt.want {
				t.Errorf("RansomwareDetector.determineThreatLevel() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRansomwareDetector_matchSignature(t *testing.T) {
	type fields struct {
		signatures  []RansomwareSignature
		behaviors   []RansomwareBehavior
		fileWatcher *FileWatcher
		thresholds  *DetectionThresholds
		handlers    []BehaviorHandler
		mu          sync.RWMutex
	}
	type args struct {
		behavior *RansomwareBehavior
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *RansomwareSignature
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &RansomwareDetector{
				signatures:  tt.fields.signatures,
				behaviors:   tt.fields.behaviors,
				fileWatcher: tt.fields.fileWatcher,
				thresholds:  tt.fields.thresholds,
				handlers:    tt.fields.handlers,
				mu:          tt.fields.mu,
			}
			if got := d.matchSignature(tt.args.behavior); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RansomwareDetector.matchSignature() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_containsSubstring(t *testing.T) {
	type args struct {
		s      string
		substr string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containsSubstring(tt.args.s, tt.args.substr); got != tt.want {
				t.Errorf("containsSubstring() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_findSubstring(t *testing.T) {
	type args struct {
		s      string
		substr string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := findSubstring(tt.args.s, tt.args.substr); got != tt.want {
				t.Errorf("findSubstring() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFileWatcher_Watch(t *testing.T) {
	type fields struct {
		watchedPaths []string
		changes      chan FileChange
		handlers     []func(FileChange)
		mu           sync.RWMutex
		started      bool
		stopped      bool
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &FileWatcher{
				watchedPaths: tt.fields.watchedPaths,
				changes:      tt.fields.changes,
				handlers:     tt.fields.handlers,
				mu:           tt.fields.mu,
				started:      tt.fields.started,
				stopped:      tt.fields.stopped,
			}
			if err := w.Watch(); (err != nil) != tt.wantErr {
				t.Errorf("FileWatcher.Watch() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFileWatcher_simulateWatching(t *testing.T) {
	type fields struct {
		watchedPaths []string
		changes      chan FileChange
		handlers     []func(FileChange)
		mu           sync.RWMutex
		started      bool
		stopped      bool
	}
	tests := []struct {
		name   string
		fields fields
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &FileWatcher{
				watchedPaths: tt.fields.watchedPaths,
				changes:      tt.fields.changes,
				handlers:     tt.fields.handlers,
				mu:           tt.fields.mu,
				started:      tt.fields.started,
				stopped:      tt.fields.stopped,
			}
			w.simulateWatching()
		})
	}
}

func TestFileWatcher_OnChange(t *testing.T) {
	type fields struct {
		watchedPaths []string
		changes      chan FileChange
		handlers     []func(FileChange)
		mu           sync.RWMutex
		started      bool
		stopped      bool
	}
	type args struct {
		handler func(FileChange)
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &FileWatcher{
				watchedPaths: tt.fields.watchedPaths,
				changes:      tt.fields.changes,
				handlers:     tt.fields.handlers,
				mu:           tt.fields.mu,
				started:      tt.fields.started,
				stopped:      tt.fields.stopped,
			}
			w.OnChange(tt.args.handler)
		})
	}
}

func TestFileWatcher_SendChange(t *testing.T) {
	type fields struct {
		watchedPaths []string
		changes      chan FileChange
		handlers     []func(FileChange)
		mu           sync.RWMutex
		started      bool
		stopped      bool
	}
	type args struct {
		change FileChange
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &FileWatcher{
				watchedPaths: tt.fields.watchedPaths,
				changes:      tt.fields.changes,
				handlers:     tt.fields.handlers,
				mu:           tt.fields.mu,
				started:      tt.fields.started,
				stopped:      tt.fields.stopped,
			}
			w.SendChange(tt.args.change)
		})
	}
}

func TestFileWatcher_GetChanges(t *testing.T) {
	type fields struct {
		watchedPaths []string
		changes      chan FileChange
		handlers     []func(FileChange)
		mu           sync.RWMutex
		started      bool
		stopped      bool
	}
	tests := []struct {
		name   string
		fields fields
		want   []FileChange
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &FileWatcher{
				watchedPaths: tt.fields.watchedPaths,
				changes:      tt.fields.changes,
				handlers:     tt.fields.handlers,
				mu:           tt.fields.mu,
				started:      tt.fields.started,
				stopped:      tt.fields.stopped,
			}
			if got := w.GetChanges(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FileWatcher.GetChanges() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isSuspiciousExtension(t *testing.T) {
	type args struct {
		ext string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSuspiciousExtension(tt.args.ext); got != tt.want {
				t.Errorf("isSuspiciousExtension() = %v, want %v", got, tt.want)
			}
		})
	}
}
