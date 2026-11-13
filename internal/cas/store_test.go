package cas

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Britnispirs/Gitsec/internal/models"
)

func TestStore_Init(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "gitsec_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	store := NewStore(tempDir)
	if err := store.Init(); err != nil {
		t.Fatalf("Store.Init() returned error: %v", err)
	}

	// Verify required directories exist
	expectedDirs := []string{
		filepath.Join(tempDir, SecDir),
		filepath.Join(tempDir, SecDir, ObjectsDir),
		filepath.Join(tempDir, SecDir, RefsDir),
		filepath.Join(tempDir, SecDir, RefsHeadsDir),
	}

	for _, dir := range expectedDirs {
		info, err := os.Stat(dir)
		if err != nil {
			t.Errorf("expected directory %s to exist, but got: %v", dir, err)
		} else if !info.IsDir() {
			t.Errorf("path %s exists but is not a directory", dir)
		}
	}

	// Verify HEAD file contents
	headPath := filepath.Join(tempDir, SecDir, HeadFile)
	headData, err := os.ReadFile(headPath)
	if err != nil {
		t.Fatalf("failed to read HEAD file: %v", err)
	}

	expectedHead := "ref: refs/heads/main\n"
	if string(headData) != expectedHead {
		t.Errorf("expected HEAD %q, got %q", expectedHead, string(headData))
	}
}

func TestStore_WriteAndReadObject(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "gitsec_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	store := NewStore(tempDir)
	if err := store.Init(); err != nil {
		t.Fatalf("store.Init() failed: %v", err)
	}

	finding := models.Finding{
		SchemaVersion: "1.0.0",
		RuleID:        "secrets/stripe-api-key",
		Fingerprint:   "fp_test_12345",
		Category:      "SECRET",
		Severity:      models.SeverityCritical,
		Title:         "Stripe API Key exposed in source",
		Location: models.FindingLocation{
			FilePath:  "src/pay.go",
			StartLine: 10,
			EndLine:   10,
		},
		Remediation: models.Remediation{
			Guidance:    "Use environment variables instead of hardcoded keys.",
			AutoFixable: false,
		},
	}

	payload, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("failed to marshal finding: %v", err)
	}

	// 1. Write object
	objectID, err := store.WriteObject(models.TypeFinding, payload)
	if err != nil {
		t.Fatalf("store.WriteObject() failed: %v", err)
	}

	if len(objectID) != 64 {
		t.Fatalf("expected 64-char hex SHA-256, got %s (len %d)", objectID, len(objectID))
	}

	// Verify sharded file location: .sec/objects/XX/YYYY...
	expectedFile := filepath.Join(tempDir, SecDir, ObjectsDir, objectID[:2], objectID[2:])
	if _, err := os.Stat(expectedFile); err != nil {
		t.Fatalf("expected object file at %s, got: %v", expectedFile, err)
	}

	// 2. Read object back
	objType, readPayload, err := store.ReadObject(objectID)
	if err != nil {
		t.Fatalf("store.ReadObject() failed: %v", err)
	}

	if objType != models.TypeFinding {
		t.Errorf("expected object type %s, got %s", models.TypeFinding, objType)
	}

	var readFinding models.Finding
	if err := json.Unmarshal(readPayload, &readFinding); err != nil {
		t.Fatalf("failed to unmarshal retrieved payload: %v", err)
	}

	if readFinding.RuleID != finding.RuleID || readFinding.Fingerprint != finding.Fingerprint {
		t.Errorf("retrieved finding mismatch: %+v vs %+v", readFinding, finding)
	}

	// 3. Deduplication check
	secondID, err := store.WriteObject(models.TypeFinding, payload)
	if err != nil {
		t.Fatalf("second WriteObject failed: %v", err)
	}
	if secondID != objectID {
		t.Errorf("deduplication failed: expected %s, got %s", objectID, secondID)
	}
}

