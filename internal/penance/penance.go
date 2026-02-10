package penance

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/adumbdinosaur/vex-cli/internal/guardian"
	"github.com/adumbdinosaur/vex-cli/internal/surveillance"
	"github.com/adumbdinosaur/vex-cli/internal/throttler"
)

// -- Interfaces --

type FileSystem interface {
	ReadFile(name string) ([]byte, error)
	WriteFile(name string, data []byte, perm os.FileMode) error
}

type RealFileSystem struct{}

func (r *RealFileSystem) ReadFile(name string) ([]byte, error) { return os.ReadFile(name) }
func (r *RealFileSystem) WriteFile(name string, data []byte, perm os.FileMode) error {
	return os.WriteFile(name, data, perm)
}

var fsOps FileSystem = &RealFileSystem{}

// -- Data Structures --

type Manifest struct {
	Version    string               `json:"manifest_version"`
	Meta       ManifestMeta         `json:"meta"`
	Active     ActivePenance        `json:"active_penance"`
	Overrides  SystemStateOverrides `json:"system_state_overrides"`
	Escalation EscalationMatrix     `json:"escalation_matrix"`
}

type ManifestMeta struct {
	TargetID      string `json:"target_id"`
	LastUpdated   string `json:"last_updated"`
	Authorization string `json:"authorization"`
}

type ActivePenance struct {
	TaskID          string              `json:"task_id"`
	Type            string              `json:"type"`
	RequiredContent ContentRequirements `json:"required_content"`
	Constraints     TaskConstraints     `json:"constraints"`
}

type ContentRequirements struct {
	Topic             string   `json:"topic"`
	MinWordCount      int      `json:"min_word_count"`
	ValidationStrings []string `json:"validation_strings"`
}

type TaskConstraints struct {
	AllowBackspace bool `json:"allow_backspace"`
	MinKPM         int  `json:"min_kpm"`
	MaxKPM         int  `json:"max_kpm"`
	EnforceRhythm  bool `json:"enforce_rhythm"`
}

type SystemStateOverrides struct {
	Network NetworkState `json:"network"`
	Compute ComputeState `json:"compute"`
}

type NetworkState struct {
	Profile      string  `json:"profile"`
	PacketLoss   float64 `json:"packet_loss_pct"`
	DNSFiltering string  `json:"dns_filtering"`
}

type ComputeState struct {
	CPULimit     int `json:"cpu_limit_pct"`
	OOMScoreAdj  int `json:"oom_score_adj"`
	InputLatency int `json:"input_latency_ms"`
}

type EscalationMatrix struct {
	Thresholds map[string]EscalationLevel `json:"score_thresholds"`
}

type EscalationLevel struct {
	TaskPool []string `json:"task_pool"`
	Latency  int      `json:"latency"`
}

// -- Global State --

var CurrentManifest *Manifest

// -- Initialization --

func Init() error {
	log.Println("Initializing Penance Subsystem...")

	m, err := LoadManifest("penance-manifest.json")
	if err != nil {
		return fmt.Errorf("failed to load manifest: %w", err)
	}

	CurrentManifest = m
	log.Printf("Penance: Loaded Manifest %s for %s", m.Version, m.Meta.TargetID)
	log.Printf("Penance: Active Task: %s (%s)", m.Active.TaskID, m.Active.Type)

	// Only enforce restrictions if a penance is actively in progress
	cs, err := LoadComplianceStatus()
	if err != nil {
		log.Printf("Penance: Could not load compliance status, skipping enforcement: %v", err)
		return nil
	}

	if !cs.Locked {
		log.Println("Penance: No active penalty (system unlocked) — skipping enforcement")
		return nil
	}

	log.Printf("Penance: System locked (score: %d, status: %s) — enforcing restrictions", cs.FailureScore, cs.TaskStatus)
	if err := m.EnforceState(); err != nil {
		return fmt.Errorf("failed to enforce system state: %w", err)
	}

	return nil
}

// IsPenaltyActive returns whether the system currently has an active penalty.
// Returns true as a fail-safe if compliance status cannot be determined.
func IsPenaltyActive() bool {
	cs, err := LoadComplianceStatus()
	if err != nil {
		return true // Fail-safe: assume active if we can't determine
	}
	return cs.Locked
}

func LoadManifest(filename string) (*Manifest, error) {
	data, err := fsOps.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// EnforceState applies the system state overrides defined in the manifest.
func (m *Manifest) EnforceState() error {
	overrides := m.Overrides

	// 1. Network Enforcement (combined profile + packet loss to avoid qdisc conflict)
	log.Printf("Penance: Enforcing Network Profile: %s (Packet Loss: %.2f%%)", overrides.Network.Profile, overrides.Network.PacketLoss)
	if err := throttler.ApplyNetworkProfileWithEntropy(
		throttler.Profile(overrides.Network.Profile),
		float32(overrides.Network.PacketLoss),
	); err != nil {
		return fmt.Errorf("failed to apply network profile with entropy: %w", err)
	}

	// 2. Compute Enforcement
	if overrides.Compute.CPULimit > 0 {
		log.Printf("Penance: Setting CPU Limit: %d%%", overrides.Compute.CPULimit)
		if err := throttler.SetCPULimit(overrides.Compute.CPULimit); err != nil {
			return fmt.Errorf("failed to set cpu limit: %w", err)
		}
	}

	// Persist the enforced state so it survives reboots
	state := &throttler.ThrottlerState{
		ActiveProfile: overrides.Network.Profile,
		PacketLossPct: float32(overrides.Network.PacketLoss),
		CPULimitPct:   overrides.Compute.CPULimit,
		ChangedBy:     "penance",
	}
	if err := throttler.SaveState(state); err != nil {
		log.Printf("Penance: Warning - failed to persist throttler state: %v", err)
	}

	if overrides.Compute.OOMScoreAdj != 0 {
		log.Printf("Penance: Adjusting OOM Score: %d", overrides.Compute.OOMScoreAdj)
		if err := guardian.SetOOMScore(overrides.Compute.OOMScoreAdj); err != nil {
			// Cleanly handle if guardian is restricted or permission denied, but return error for visibility
			return fmt.Errorf("failed to set oom score: %w", err)
		}
	}

	// 3. Input Latency
	if overrides.Compute.InputLatency > 0 {
		log.Printf("Penance: Injecting Input Latency: %dms", overrides.Compute.InputLatency)
		if err := surveillance.InjectLatency(overrides.Compute.InputLatency); err != nil {
			return fmt.Errorf("failed to inject input latency: %w", err)
		}
	}

	return nil
}

// -- Compliance Status Tracking --

const complianceStatusFile = "compliance-status.json"

// ComplianceStatus tracks the subject's compliance state and failure score
type ComplianceStatus struct {
	FailureScore   int    `json:"failure_score"`
	ActiveTask     string `json:"active_task"`
	TaskStatus     string `json:"task_status"` // "pending", "in_progress", "completed", "failed"
	LastUpdated    string `json:"last_updated"`
	TotalFailures  int    `json:"total_failures"`
	TotalCompleted int    `json:"total_completed"`
	Locked         bool   `json:"locked"`
}

// LoadComplianceStatus reads the current compliance status from disk
func LoadComplianceStatus() (*ComplianceStatus, error) {
	data, err := fsOps.ReadFile(complianceStatusFile)
	if err != nil {
		// If not found, create default
		if os.IsNotExist(err) {
			cs := &ComplianceStatus{
				FailureScore: 0,
				TaskStatus:   "pending",
				Locked:       true,
				LastUpdated:  time.Now().UTC().Format(time.RFC3339),
			}
			return cs, nil
		}
		return nil, err
	}

	var cs ComplianceStatus
	if err := json.Unmarshal(data, &cs); err != nil {
		return nil, err
	}
	return &cs, nil
}

// SaveComplianceStatus persists the compliance status to disk
func SaveComplianceStatus(cs *ComplianceStatus) error {
	cs.LastUpdated = time.Now().UTC().Format(time.RFC3339)
	data, err := json.MarshalIndent(cs, "", "  ")
	if err != nil {
		return err
	}
	return fsOps.WriteFile(complianceStatusFile, data, 0644)
}

// RecordFailure increments the failure score and total failures
func RecordFailure(reason string) error {
	cs, err := LoadComplianceStatus()
	if err != nil {
		return fmt.Errorf("failed to load compliance status: %w", err)
	}

	cs.FailureScore += 10
	cs.TotalFailures++
	cs.TaskStatus = "failed"
	cs.Locked = true

	log.Printf("Penance: FAILURE recorded (%s). Score: %d", reason, cs.FailureScore)
	return SaveComplianceStatus(cs)
}

// RecordCompletion marks the current task as completed
func RecordCompletion() error {
	cs, err := LoadComplianceStatus()
	if err != nil {
		return fmt.Errorf("failed to load compliance status: %w", err)
	}

	cs.TotalCompleted++
	cs.TaskStatus = "completed"
	cs.Locked = false

	log.Printf("Penance: Task COMPLETED. Total completions: %d", cs.TotalCompleted)
	return SaveComplianceStatus(cs)
}

// SelectWeightedTask selects a task type based on the current failure score
// using the escalation matrix. Higher failure scores shift toward harder tasks.
func SelectWeightedTask(m *Manifest) string {
	cs, err := LoadComplianceStatus()
	if err != nil {
		log.Printf("Penance: Could not load compliance status for weighting: %v", err)
		return m.Active.Type
	}

	// Find the highest threshold that the failure score exceeds
	bestThreshold := ""
	bestLevel := EscalationLevel{}
	for threshold, level := range m.Escalation.Thresholds {
		var t int
		fmt.Sscanf(threshold, "%d", &t)
		if cs.FailureScore >= t {
			var bt int
			fmt.Sscanf(bestThreshold, "%d", &bt)
			if t >= bt {
				bestThreshold = threshold
				bestLevel = level
			}
		}
	}

	if len(bestLevel.TaskPool) > 0 {
		// Select from the pool (use deterministic selection based on time for simplicity)
		idx := int(time.Now().UnixNano()) % len(bestLevel.TaskPool)
		selected := bestLevel.TaskPool[idx]
		log.Printf("Penance: Dynamic weighting selected task type '%s' (score: %d, threshold: %s)",
			selected, cs.FailureScore, bestThreshold)
		return selected
	}

	return m.Active.Type
}

// -- Submission Validation --

// ValidationResult holds the result of validating a penance submission
type ValidationResult struct {
	Valid  bool
	Errors []string
}

// ValidateSubmission checks a submission against the active penance constraints
func ValidateSubmission(text string, m *Manifest) *ValidationResult {
	result := &ValidationResult{Valid: true}
	req := m.Active.RequiredContent
	constraints := m.Active.Constraints

	// 1. Word count check
	words := strings.Fields(text)
	wordCount := len(words)
	if wordCount < req.MinWordCount {
		result.Valid = false
		result.Errors = append(result.Errors,
			fmt.Sprintf("Word count insufficient: %d/%d", wordCount, req.MinWordCount))
	}

	// 2. Validation strings check
	for _, phrase := range req.ValidationStrings {
		if !strings.Contains(text, phrase) {
			result.Valid = false
			result.Errors = append(result.Errors,
				fmt.Sprintf("Missing required phrase: \"%s\"", phrase))
		}
	}

	// 3. KPM validation (checked against surveillance metrics)
	if constraints.EnforceRhythm && constraints.MinKPM > 0 {
		kpm := surveillance.GetCurrentKPM()
		if kpm > 0 { // Only validate if we have data
			if int(kpm) < constraints.MinKPM {
				result.Valid = false
				result.Errors = append(result.Errors,
					fmt.Sprintf("Typing speed too slow: %.1f KPM (minimum: %d KPM)", kpm, constraints.MinKPM))
			}
			if constraints.MaxKPM > 0 && int(kpm) > constraints.MaxKPM {
				result.Valid = false
				result.Errors = append(result.Errors,
					fmt.Sprintf("Typing speed suspiciously fast: %.1f KPM (maximum: %d KPM). Paste detected?", kpm, constraints.MaxKPM))
			}
		}
	}

	return result
}

// ValidateLineInput checks a single line for the allow_backspace constraint.
// Returns true if the line is valid, false if a backspace was detected.
func ValidateLineInput(line string, constraints TaskConstraints) bool {
	if !constraints.AllowBackspace {
		// Check if the line contains any backspace characters
		if strings.ContainsRune(line, '\b') || strings.ContainsRune(line, 127) {
			return false
		}
	}
	return true
}