// Package detect provides ransomware behavior detection capabilities.
package detect

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DetectionMethod represents how ransomware is detected.
type DetectionMethod string

const (
	MethodFileChange DetectionMethod = "file_change"
	MethodEncryption DetectionMethod = "encryption_pattern"
	MethodProcess    DetectionMethod = "suspicious_process"
	MethodBehavior   DetectionMethod = "behavioral_analysis"
	MethodNetwork    DetectionMethod = "network_activity"
)

// RansomwareSignature represents a ransomware signature/pattern.
type RansomwareSignature struct {
	ID               string
	Name             string
	Family           string
	Severity         string
	Indicators       []string
	Hashes           []string
	BehaviorPatterns []string
	FirstSeen        time.Time
}

// FileChange represents a file system change.
type FileChange struct {
	Path        string
	Operation   string // create, modify, delete, rename
	OriginalExt string
	NewExt      string
	TimeStamp   time.Time
	Size        int64
	IsEncrypted bool
}

// RansomwareBehavior represents detected ransomware behavior.
type RansomwareBehavior struct {
	ID             string
	Timestamp      time.Time
	Method         DetectionMethod
	Confidence     float64
	Score          float64
	FilesAffected  int
	FilesPerSecond float64
	EncryptionRate float64
	Signature      *RansomwareSignature
	ProcessInfo    map[string]string
	Evidence       []string
	IsMalicious    bool
	ThreatLevel    string
}

// FileWatcher monitors file system for ransomware behavior.
type FileWatcher struct {
	watchedPaths []string
	changes      chan FileChange
	handlers     []func(FileChange)
	mu           sync.RWMutex
	started      bool
	stopped      bool
}

// RansomwareDetector detects ransomware activity.
type RansomwareDetector struct {
	signatures  []RansomwareSignature
	behaviors   []RansomwareBehavior
	fileWatcher *FileWatcher
	thresholds  *DetectionThresholds
	handlers    []BehaviorHandler
	mu          sync.RWMutex
}

// DetectionThresholds contains detection thresholds.
type DetectionThresholds struct {
	FilesPerSecond      float64
	EncryptionRate      float64
	ConfidenceThreshold float64
	MinFilesAffected    int
	MaxTimeWindow       time.Duration
}

// BehaviorHandler handles detected ransomware behavior.
type BehaviorHandler func(*RansomwareBehavior) error

// NewRansomwareDetector creates a new ransomware detector.
func NewRansomwareDetector() *RansomwareDetector {
	return &RansomwareDetector{
		signatures: make([]RansomwareSignature, 0),
		behaviors:  make([]RansomwareBehavior, 0),
		thresholds: &DetectionThresholds{
			FilesPerSecond:      10.0,
			EncryptionRate:      0.8,
			ConfidenceThreshold: 0.7,
			MinFilesAffected:    50,
			MaxTimeWindow:       60 * time.Second,
		},
	}
}

// AddSignature adds a ransomware signature.
func (d *RansomwareDetector) AddSignature(sig RansomwareSignature) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.signatures = append(d.signatures, sig)
}

// GetSignatures returns all signatures.
func (d *RansomwareDetector) GetSignatures() []RansomwareSignature {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.signatures
}

// SetThresholds sets detection thresholds.
func (d *RansomwareDetector) SetThresholds(thresholds DetectionThresholds) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.thresholds = &thresholds
}

// GetThresholds returns current thresholds.
func (d *RansomwareDetector) GetThresholds() DetectionThresholds {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return *d.thresholds
}

// RegisterHandler registers a behavior handler.
func (d *RansomwareDetector) RegisterHandler(handler BehaviorHandler) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.handlers = append(d.handlers, handler)
}

// DetectBehavior analyzes file changes for ransomware patterns.
func (d *RansomwareDetector) DetectBehavior(changes []FileChange) []*RansomwareBehavior {
	if len(changes) == 0 {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Analyze changes
	behavior := &RansomwareBehavior{
		ID:            fmt.Sprintf("beh-%d", time.Now().UnixNano()),
		Timestamp:     time.Now(),
		Method:        MethodFileChange,
		Confidence:    0.0,
		Score:         0.0,
		FilesAffected: len(changes),
		Evidence:      make([]string, 0),
	}

	// Calculate files per second
	if len(changes) > 1 {
		behavior.FilesPerSecond = float64(len(changes)) / float64(changes[len(changes)-1].TimeStamp.Sub(changes[0].TimeStamp).Seconds())
	}

	// Calculate encryption rate
	encFiles := 0
	for _, change := range changes {
		if change.IsEncrypted {
			encFiles++
			behavior.Evidence = append(behavior.Evidence, fmt.Sprintf("Encrypted: %s", change.Path))
		}
	}
	if len(changes) > 0 {
		behavior.EncryptionRate = float64(encFiles) / float64(len(changes))
	}

	// Calculate confidence and threat level
	behavior.Confidence = d.calculateConfidence(behavior)
	behavior.ThreatLevel = d.determineThreatLevel(behavior)
	behavior.IsMalicious = behavior.Confidence >= d.thresholds.ConfidenceThreshold

	// Check against signatures
	behavior.Signature = d.matchSignature(behavior)

	// Store behavior
	d.behaviors = append(d.behaviors, *behavior)

	// Trigger handlers
	for _, handler := range d.handlers {
		_ = handler(behavior)
	}

	return []*RansomwareBehavior{behavior}
}

// calculateConfidence calculates detection confidence.
func (d *RansomwareDetector) calculateConfidence(behavior *RansomwareBehavior) float64 {
	confidence := 0.0

	// Files per second factor
	if behavior.FilesPerSecond > d.thresholds.FilesPerSecond*2 {
		confidence += 0.3
	} else if behavior.FilesPerSecond > d.thresholds.FilesPerSecond {
		confidence += 0.2
	}

	// Encryption rate factor
	if behavior.EncryptionRate > 0.9 {
		confidence += 0.3
	} else if behavior.EncryptionRate > 0.7 {
		confidence += 0.2
	}

	// Files affected factor
	if behavior.FilesAffected > 1000 {
		confidence += 0.2
	} else if behavior.FilesAffected > 100 {
		confidence += 0.1
	}

	// Evidence factor
	confidence += float64(len(behavior.Evidence)) * 0.02

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// determineThreatLevel determines threat level.
func (d *RansomwareDetector) determineThreatLevel(behavior *RansomwareBehavior) string {
	if behavior.IsMalicious && behavior.Signature != nil {
		return "CRITICAL"
	} else if behavior.Confidence >= 0.9 {
		return "HIGH"
	} else if behavior.Confidence >= 0.7 {
		return "MEDIUM"
	} else if behavior.Confidence >= 0.5 {
		return "LOW"
	}
	return "MINIMAL"
}

// matchSignature matches behavior against known signatures.
func (d *RansomwareDetector) matchSignature(behavior *RansomwareBehavior) *RansomwareSignature {
	for _, sig := range d.signatures {
		// Check if behavior indicators match signature
		matches := 0
		for _, indicator := range sig.Indicators {
			for _, evidence := range behavior.Evidence {
				if containsSubstring(evidence, indicator) {
					matches++
					break
				}
			}
		}

		// If enough matches, consider it a match
		if matches >= len(sig.Indicators)/2 {
			return &sig
		}
	}
	return nil
}

// containsSubstring checks if string contains substring.
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// NewFileWatcher creates a new file watcher.
func NewFileWatcher(paths []string) *FileWatcher {
	return &FileWatcher{
		watchedPaths: paths,
		changes:      make(chan FileChange, 1000),
		handlers:     make([]func(FileChange), 0),
	}
}

// Watch starts watching paths for changes.
func (w *FileWatcher) Watch() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.started {
		return fmt.Errorf("watcher already started")
	}

	w.started = true

	// In production: use inotify/fsevents for file watching
	// For demo: simulate watching
	go w.simulateWatching()

	return nil
}

// simulateWatching simulates file watching.
func (w *FileWatcher) simulateWatching() {
	// In production: implement actual file system monitoring
	// This is a placeholder for actual implementation
}

// OnChange registers a change handler.
func (w *FileWatcher) OnChange(handler func(FileChange)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.handlers = append(w.handlers, handler)
}

// SendChange sends a file change.
func (w *FileWatcher) SendChange(change FileChange) {
	w.changes <- change
}

// GetChanges returns pending changes.
func (w *FileWatcher) GetChanges() []FileChange {
	var changes []FileChange
	for {
		select {
		case change := <-w.changes:
			changes = append(changes, change)
		default:
			return changes
		}
	}
}

// ScanDirectory scans directory for suspicious files.
func ScanDirectory(dir string) ([]FileChange, error) {
	var changes []FileChange

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			ext := filepath.Ext(path)
			// Check for suspicious extensions
			if isSuspiciousExtension(ext) {
				changes = append(changes, FileChange{
					Path:        path,
					Operation:   "suspicious_file",
					OriginalExt: ext,
					TimeStamp:   time.Now(),
					Size:        info.Size(),
				})
			}
		}

		return nil
	})

	return changes, err
}

// isSuspiciousExtension checks if extension is suspicious.
func isSuspiciousExtension(ext string) bool {
	suspiciousExts := []string{
		".locked", ".encrypted", ".enc", ".crypto", ".crypt",
		".ransom", ".toxor", ".wannacry", ".petya", ".globe",
	}
	for _, s := range suspiciousExts {
		if ext == s {
			return true
		}
	}
	return false
}

// GetBehavior returns behavior.
func GetBehavior(behavior *RansomwareBehavior) *RansomwareBehavior {
	return behavior
}

// GetDetector returns detector.
func GetDetector(detector *RansomwareDetector) *RansomwareDetector {
	return detector
}
