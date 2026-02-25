# ransomseeker - Ransomware Behavior Detection & Prevention

[![Go](https://img.shields.io/badge/Go-1.21-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

**Detect and prevent ransomware attacks with behavioral analysis.**

Monitor file system activity, detect ransomware patterns, and protect critical data.

## 🚀 Features

- **Behavioral Detection**: Detect ransomware by analyzing file system behavior
- **Pattern Recognition**: Identify known ransomware signatures
- **Real-time Protection**: Block ransomware execution in real-time
- **File Protection**: Protect critical files from modification
- **Recovery Engine**: Restore files from snapshots and backups
- **Comprehensive Reporting**: Detailed detection and recovery reports

## 📦 Installation

### Build from Source

```bash
git clone https://github.com/hallucinaut/ransomseeker.git
cd ransomseeker
go build -o ransomseeker ./cmd/ransomseeker
sudo mv ransomseeker /usr/local/bin/
```

### Install via Go

```bash
go install github.com/hallucinaut/ransomseeker/cmd/ransomseeker@latest
```

## 🎯 Usage

### Detect Ransomware

```bash
# Detect ransomware behavior
ransomseeker detect
```

### Protect Files

```bash
# Start file protection
ransomseeker protect
```

### Recover Files

```bash
# Recover from ransomware attack
ransomseeker recover
```

### Scan Directory

```bash
# Scan directory for suspicious files
ransomseeker scan /path/to/scan
```

### Generate Report

```bash
# Generate comprehensive report
ransomseeker report
```

### Programmatic Usage

```go
package main

import (
    "fmt"
    "github.com/hallucinaut/ransomseeker/pkg/detect"
    "github.com/hallucinaut/ransomseeker/pkg/protect"
    "github.com/hallucinaut/ransomseeker/pkg/recovery"
)

func main() {
    // Create detector
    detector := detect.NewRansomwareDetector()
    
    // Add known signatures
    sig := detect.RansomwareSignature{
        ID:       "sig-001",
        Name:     "WannaCry",
        Family:   "WannaCry",
        Severity: "CRITICAL",
        Indicators: []string{".wcry", "ransom"},
    }
    detector.AddSignature(sig)
    
    // Detect behavior
    changes := []detect.FileChange{
        {Path: "/home/file.encrypted", IsEncrypted: true},
    }
    behaviors := detector.DetectBehavior(changes)
    fmt.Printf("Behaviors detected: %d\n", len(behaviors))
    
    // Create protection engine
    protectEngine := protect.NewProtectionEngine()
    protectEngine.StartProtection(protect.StrategyBlocking)
    
    // Create recovery engine
    recoveryEngine := recovery.NewRecoveryEngine()
    plan := recovery.CreateCommonPlans()[0]
    recoveryEngine.AddPlan(plan)
    
    // Execute recovery
    result := recoveryEngine.ExecutePlan(plan.ID, []string{"/home/infected"})
    fmt.Printf("Recovery status: %s\n", result.Status)
}
```

## 📚 Detection Methods

### File Change Detection
- Monitor file creation, modification, deletion
- Track file extension changes
- Detect bulk file operations

### Encryption Pattern Detection
- Identify rapid file encryption
- Monitor file size changes
- Detect encryption indicators

### Process Monitoring
- Track suspicious processes
- Monitor process behavior
- Detect malicious execution

### Behavioral Analysis
- Analyze file access patterns
- Detect ransomware-like behavior
- Calculate threat confidence

## 🧪 Ransomware Signatures

Supports detection of known ransomware families:

| Family | Signature | Severity |
|--------|-----------|----------|
| WannaCry | sig-001 | CRITICAL |
| Ryuk | sig-002 | CRITICAL |
| LockBit | sig-003 | CRITICAL |
| Conti | sig-004 | CRITICAL |
| Phobos | sig-005 | CRITICAL |

## 🏗️ Architecture

```
ransomseeker/
├── cmd/
│   └── ransomseeker/
│       └── main.go          # CLI entry point
├── pkg/
│   ├── detect/
│   │   ├── detect.go       # Detection engine
│   │   └── detect_test.go  # Unit tests
│   ├── protect/
│   │   ├── protect.go      # Protection engine
│   │   └── protect_test.go # Unit tests
│   └── recovery/
│       ├── recovery.go     # Recovery engine
│       └── recovery_test.go # Unit tests
└── README.md
```

## 🧪 Testing

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific test
go test -v ./pkg/detect -run TestDetectBehavior
```

## 📋 Example Output

```
$ ransomseeker detect

Ransomware Behavior Detection
==============================

Detection Results:

[1] Behavior ID: beh-1234567890
    Method: file_change
    Confidence: 95.0%
    Threat Level: HIGH
    Files Affected: 150
    Files/Second: 12.5
    Encryption Rate: 98.0%
    Is Malicious: true
    Signature Match: WannaCry (WannaCry)
```

## 🔒 Security Use Cases

- **Ransomware Detection**: Detect ransomware in real-time
- **File Protection**: Protect critical files from encryption
- **Incident Response**: Recover from ransomware attacks
- **Threat Hunting**: Investigate ransomware incidents
- **Forensics**: Collect evidence of ransomware activity

## 🛡️ Best Practices

1. **Enable real-time protection** - Monitor file system continuously
2. **Maintain backups** - Keep offline backups for recovery
3. **Regular scans** - Scan systems regularly for indicators
4. **Keep signatures updated** - Update ransomware signatures
5. **Monitor critical files** - Protect important data
6. **Test recovery** - Regularly test recovery procedures

## 📄 License

MIT License

## 🙏 Acknowledgments

- Ransomware researchers
- Security community
- Threat intelligence providers

## 🔗 Resources

- [No More Ransom](https://www.nomoreransom.org/)
- [MalwareBazaar](https://bazaar.abuse.ch/)
- [VirusTotal](https://www.virustotal.com/)
- [Any.Run](https://any.run/)

---

**build with GPU by [hallucinaut](https://github.com/hallucinaut)**