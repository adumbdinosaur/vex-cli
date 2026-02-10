// Package state provides the unified persisted system state for vex-cli.
// Both the daemon (vexd) and the CLI write/read this file as the single
// source of truth for what the system should look like on any given boot.
package state

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// StateDir is the base directory for all vex-cli runtime state.
	StateDir = "/var/lib/vex-cli"

	// StateFile is the unified system state persisted to disk.
	StateFile = "/var/lib/vex-cli/system-state.json"

	// SocketPath is the Unix domain socket for CLI ↔ daemon IPC.
	SocketPath = "/run/vex-cli/vexd.sock"
)

// SystemState is the single file that captures every enforceable setting.
// The daemon reads it on startup and applies each section.
// The CLI (via IPC) asks the daemon to mutate sections and persist.
type SystemState struct {
	Version     string         `json:"version"`
	LastUpdated string         `json:"last_updated"`
	ChangedBy   string         `json:"changed_by"` // "cli", "penance", "unlock", "daemon", "escalation"
	Network     NetworkState   `json:"network"`
	Compute     ComputeState   `json:"compute"`
	Guardian    GuardianState  `json:"guardian"`
	Compliance  ComplianceInfo `json:"compliance"`
	Writing     WritingTask    `json:"writing"`
}

// NetworkState holds all network-shaping parameters.
type NetworkState struct {
	Profile       string  `json:"profile"`         // standard, choke, dial-up, black-hole
	PacketLossPct float32 `json:"packet_loss_pct"` // 0-100
}

// ComputeState holds CPU / OOM / latency overrides.
type ComputeState struct {
	CPULimitPct    int `json:"cpu_limit_pct"`     // 0-100  (100 = uncapped)
	OOMScoreAdj    int `json:"oom_score_adj"`     // -1000 to 1000
	InputLatencyMs int `json:"input_latency_ms"`  // 0 = none
}

// GuardianState holds process-reaper and firewall config.
type GuardianState struct {
	FirewallEnabled bool     `json:"firewall_enabled"` // SNI blocking active
	ReaperEnabled   bool     `json:"reaper_enabled"`   // Process reaper active
	BlockedDomains  []string `json:"blocked_domains"`  // Currently blocked SNI domains
}

// WritingTask represents a "write lines" punishment: the subject must
// type an exact phrase a set number of times before the task is cleared.
// The task persists across reboots until all lines are submitted.
type WritingTask struct {
	Active    bool   `json:"active"`
	Phrase    string `json:"phrase"`
	Required  int    `json:"required"`   // total lines to write
	Completed int    `json:"completed"`  // lines accepted so far
}

// ComplianceInfo is a snapshot included for convenience — the authoritative
// copy is still compliance-status.json owned by the penance package.
type ComplianceInfo struct {
	Locked       bool   `json:"locked"`
	FailureScore int    `json:"failure_score"`
	TaskStatus   string `json:"task_status"`
}

// FileOps is abstracted for testing.
type FileOps interface {
	ReadFile(name string) ([]byte, error)
	WriteFile(name string, data []byte, perm os.FileMode) error
	MkdirAll(path string, perm os.FileMode) error
	Stat(name string) (os.FileInfo, error)
}

type RealFileOps struct{}

func (r *RealFileOps) ReadFile(name string) ([]byte, error)  { return os.ReadFile(name) }
func (r *RealFileOps) WriteFile(name string, data []byte, perm os.FileMode) error {
	return os.WriteFile(name, data, perm)
}
func (r *RealFileOps) MkdirAll(path string, perm os.FileMode) error { return os.MkdirAll(path, perm) }
func (r *RealFileOps) Stat(name string) (os.FileInfo, error)        { return os.Stat(name) }

var (
	fsOps FileOps = &RealFileOps{}
	mu    sync.Mutex
)

// Default returns a clean "no restrictions" state.
func Default() *SystemState {
	return &SystemState{
		Version:     "1.0",
		LastUpdated: time.Now().UTC().Format(time.RFC3339),
		ChangedBy:   "default",
		Network: NetworkState{
			Profile:       "standard",
			PacketLossPct: 0,
		},
		Compute: ComputeState{
			CPULimitPct:    100,
			OOMScoreAdj:    0,
			InputLatencyMs: 0,
		},
		Guardian: GuardianState{
			FirewallEnabled: false,
			ReaperEnabled:   true,
			BlockedDomains:  []string{},
		},
		Compliance: ComplianceInfo{
			Locked:       false,
			FailureScore: 0,
			TaskStatus:   "pending",
		},
	}
}

// Load reads the persisted system state from disk.
// Returns Default() if the file doesn't exist yet.
func Load() (*SystemState, error) {
	mu.Lock()
	defer mu.Unlock()

	data, err := fsOps.ReadFile(StateFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("State: No persisted state found, using defaults")
			return Default(), nil
		}
		return nil, fmt.Errorf("failed to read state file: %w", err)
	}

	var s SystemState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("failed to parse state file: %w", err)
	}
	return &s, nil
}

// Save persists the system state to disk. It ensures the directory exists.
func Save(s *SystemState) error {
	mu.Lock()
	defer mu.Unlock()

	s.LastUpdated = time.Now().UTC().Format(time.RFC3339)

	dir := filepath.Dir(StateFile)
	if _, err := fsOps.Stat(dir); os.IsNotExist(err) {
		if err := fsOps.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create state directory: %w", err)
		}
	}

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	if err := fsOps.WriteFile(StateFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write state file: %w", err)
	}

	log.Printf("State: Persisted (profile=%s, cpu=%d%%, locked=%v, by=%s)",
		s.Network.Profile, s.Compute.CPULimitPct, s.Compliance.Locked, s.ChangedBy)
	return nil
}

// EnsureSocketDir creates /run/vex-cli/ if it doesn't exist.
func EnsureSocketDir() error {
	dir := filepath.Dir(SocketPath)
	if _, err := fsOps.Stat(dir); os.IsNotExist(err) {
		return fsOps.MkdirAll(dir, 0755)
	}
	return nil
}
