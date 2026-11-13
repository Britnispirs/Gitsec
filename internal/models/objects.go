package models

import "time"

// ObjectType defines the primitive object types in Gitsec CAS.
type ObjectType string

const (
	TypeSnapshot ObjectType = "snapshot"
	TypeFinding  ObjectType = "finding"
	TypeEvidence ObjectType = "evidence"
	TypePolicy   ObjectType = "policy"
)

// PostureStatus reflects the aggregated security health of a snapshot.
type PostureStatus string

const (
	PostureClean    PostureStatus = "CLEAN"
	PostureDegraded PostureStatus = "DEGRADED"
	PostureCritical PostureStatus = "CRITICAL"
)

// Severity defines finding severity levels.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Author captures the identity of the person or CI identity creating a snapshot.
type Author struct {
	Name      string `json:"name"`
	Email     string `json:"email"`
	Timestamp int64  `json:"timestamp"`
}

// Summary captures aggregated metrics for high-level status and diff checks.
type Summary struct {
	Posture         PostureStatus `json:"posture"`
	CriticalCount   int           `json:"critical_count"`
	HighCount       int           `json:"high_count"`
	MediumCount     int           `json:"medium_count"`
	LowCount        int           `json:"low_count"`
	SuppressedCount int           `json:"suppressed_count"`
}

// SnapshotTree holds cryptographic references (SHA-256 ObjectIDs) to findings, evidence, and policy.
type SnapshotTree struct {
	Findings []string `json:"findings"`
	Evidence []string `json:"evidence"`
	Policy   string   `json:"policy"`
}

// Snapshot represents a point-in-time security audit bound to a Git commit.
type Snapshot struct {
	SchemaVersion string       `json:"schema_version"`
	GitCommit     string       `json:"git_commit"`
	Parents       []string     `json:"parents"`
	Author        Author       `json:"author"`
	Summary       Summary      `json:"summary"`
	Tree          SnapshotTree `json:"tree"`
	Message       string       `json:"message"`
}

// FindingLocation points to exact coordinates in source code.
type FindingLocation struct {
	FilePath  string `json:"file_path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	StartCol  int    `json:"start_col,omitempty"`
	EndCol    int    `json:"end_col,omitempty"`
}

// FindingContext contains relevant code snippets.
type FindingContext struct {
	Snippet string `json:"snippet,omitempty"`
}

// Remediation offers actionable guidance and automated fix information.
type Remediation struct {
	Guidance    string `json:"guidance"`
	AutoFixable bool   `json:"auto_fixable"`
}

// Finding represents an individual vulnerability, misconfiguration, or secret.
type Finding struct {
	SchemaVersion string          `json:"schema_version"`
	RuleID        string          `json:"rule_id"`
	Fingerprint   string          `json:"fingerprint"`
	Category      string          `json:"category"`
	Severity      Severity        `json:"severity"`
	Title         string          `json:"title"`
	Location      FindingLocation `json:"location"`
	Context       FindingContext  `json:"context,omitempty"`
	Remediation   Remediation     `json:"remediation"`
}

// VerifierMeta describes the tool that produced an evidence record.
type VerifierMeta struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	BinaryHash string `json:"binary_hash,omitempty"`
}

// ExecutionMeta records execution duration and exit conditions.
type ExecutionMeta struct {
	StartedAt  int64 `json:"started_at"`
	FinishedAt int64 `json:"finished_at"`
	DurationMS int64 `json:"duration_ms"`
	ExitCode   int   `json:"exit_code"`
}

// EvidenceInputs records what files/trees the verifier inspected.
type EvidenceInputs struct {
	GitTreeHash string   `json:"git_tree_hash"`
	TargetPaths []string `json:"target_paths"`
}

// Evidence represents verifiable proof that a verification run occurred.
type Evidence struct {
	SchemaVersion   string         `json:"schema_version"`
	Verifier        VerifierMeta   `json:"verifier"`
	Execution       ExecutionMeta  `json:"execution"`
	Inputs          EvidenceInputs `json:"inputs"`
	RawOutputSHA256 string         `json:"raw_output_sha256"`
}

// PolicyRules configures the thresholds for determining posture health.
type PolicyRules struct {
	FailOnSeverity            []Severity `json:"fail_on_severity"`
	AllowUnresolvedMediumDays int        `json:"allow_unresolved_medium_days"`
	ForbiddenCategories       []string   `json:"forbidden_categories"`
}

// PolicyException allows temporary waivers with expiration.
type PolicyException struct {
	FindingFingerprint string    `json:"finding_fingerprint"`
	Reason             string    `json:"reason"`
	ApprovedBy         string    `json:"approved_by"`
	ExpiresAt          time.Time `json:"expires_at"`
}

// Policy represents the versioned decision rules applied to evaluate findings.
type Policy struct {
	SchemaVersion string            `json:"schema_version"`
	Name          string            `json:"name"`
	Rules         PolicyRules       `json:"rules"`
	Exceptions    []PolicyException `json:"exceptions"`
}

