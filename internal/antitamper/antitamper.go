package antitamper

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/adumbdinosaur/vex-cli/internal/penance"
	"github.com/adumbdinosaur/vex-cli/internal/security"
	"github.com/adumbdinosaur/vex-cli/internal/throttler"
)

// -- Interfaces for Testing --

type CommandRunner interface {
	Run(name string, args ...string) ([]byte, error)
}

type RealCommandRunner struct{}

func (r *RealCommandRunner) Run(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.CombinedOutput()
}

var cmdRunner CommandRunner = &RealCommandRunner{}

// -- Configuration --

var (
	// ExpectedBinaryHash should be set at build time or from a trusted config
	ExpectedBinaryHash string

	// CheckInterval controls how often integrity checks run
	CheckInterval = 60 * time.Second

	// EscalationCooldown prevents repeated escalations from compounding
	// the failure score in a tight loop. After an escalation fires, the
	// next one is suppressed until this duration elapses.
	EscalationCooldown = 30 * time.Minute

	// MaxFailureScore caps the failure score to prevent runaway inflation.
	MaxFailureScore = 500

	lastEscalation   time.Time
	escalationMu     sync.Mutex
)

// Init starts the anti-tamper detection subsystem
func Init() error {
	log.Println("Initializing Anti-Tamper Subsystem...")

	// Perform initial integrity checks
	if err := RunAllChecks(); err != nil {
		log.Printf("Anti-Tamper: Initial check detected issues: %v", err)
		// Don't return error - escalation is handled internally
	}

	// Start periodic monitoring
	go periodicMonitor()

	log.Println("Anti-Tamper: Monitoring active")
	return nil
}

// RunAllChecks performs all integrity verification checks
func RunAllChecks() error {
	var errors []string

	// 1. Binary self-verification (if hash is set)
	if ExpectedBinaryHash != "" && ExpectedBinaryHash != "SET_AT_RUNTIME" {
		if err := security.VerifyBinaryIntegrity(ExpectedBinaryHash); err != nil {
			errors = append(errors, fmt.Sprintf("Binary integrity: %v", err))
		}
	}

	// 2. NixOS configuration integrity
	if err := verifyNixConfig(); err != nil {
		errors = append(errors, fmt.Sprintf("NixOS config: %v", err))
	}

	// 3. Service file integrity
	if err := verifyServiceIntegrity(); err != nil {
		errors = append(errors, fmt.Sprintf("Service integrity: %v", err))
	}

	if len(errors) > 0 {
		// ESCALATION: Tamper detected
		escalate(errors)
		return fmt.Errorf("tamper detected: %s", strings.Join(errors, "; "))
	}

	return nil
}

// verifyNixConfig checks the NixOS system configuration against the Nix store
// to detect manual overrides or unauthorized changes.
func verifyNixConfig() error {
	// 0. Check if running as a service first — if the unit file doesn't exist,
	//    skip all integrity checks (e.g. running outside systemd, in development,
	//    or inside a container).
	unitOutput, unitErr := cmdRunner.Run("systemctl", "cat", "vex-cli.service")
	if unitErr != nil {
		// Unit file not found — not a systemd-managed install; skip all checks.
		log.Printf("Anti-Tamper: vex-cli.service unit not found, skipping all Nix integrity checks")
		return nil
	}
	_ = unitOutput // unit exists

	// 1. Nix store integrity — only flag actual corruption, not warnings.
	output, err := cmdRunner.Run("nix-store", "--verify", "--check-contents")
	if err != nil {
		outStr := string(output)
		if strings.Contains(outStr, "path") && strings.Contains(outStr, "corrupt") {
			return fmt.Errorf("nix store corruption detected: %s", outStr)
		}
		// Non-zero exit with no corruption keyword is a harmless warning.
		log.Printf("Anti-Tamper: nix-store verify output (non-critical): %s", outStr)
	}

	// 2. NixOS state version — informational only; absence doesn't imply tamper.
	if _, err := cmdRunner.Run("nix-instantiate", "--eval", "-E",
		"(import <nixpkgs/nixos> {}).config.system.stateVersion"); err != nil {
		log.Printf("Anti-Tamper: Could not verify NixOS state version: %v (non-critical)", err)
	}

	// 3. Service check — verify the service is actually running.
	statusOutput, statusErr := cmdRunner.Run("systemctl", "is-active", "vex-cli.service")
	statusStr := strings.TrimSpace(string(statusOutput))
	if statusErr != nil || statusStr != "active" {
		return fmt.Errorf("vex-cli.service unit exists but is not active (status: %s)", statusStr)
	}

	return nil
}

// verifyServiceIntegrity checks that enforcement services are running properly
func verifyServiceIntegrity() error {
	// Check that our process hasn't been ptrace'd or debugged
	output, err := cmdRunner.Run("cat", "/proc/self/status")
	if err != nil {
		return fmt.Errorf("could not read process status: %w", err)
	}

	// Check TracerPid - if non-zero, someone is debugging us
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "TracerPid:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 && parts[1] != "0" {
				return fmt.Errorf("DEBUGGER DETECTED: TracerPid=%s", parts[1])
			}
		}
	}

	return nil
}

// escalate triggers automatic escalation when tampering is detected.
// It enforces a cooldown so that repeated periodic-check failures cannot
// compound the score in an exponential loop, and caps the score to
// prevent runaway inflation.
func escalate(reasons []string) {
	escalationMu.Lock()
	defer escalationMu.Unlock()

	log.Printf("Anti-Tamper: ⚠️ ESCALATION TRIGGERED: %v", reasons)

	// Cooldown: suppress score inflation if we already escalated recently.
	if !lastEscalation.IsZero() && time.Since(lastEscalation) < EscalationCooldown {
		log.Printf("Anti-Tamper: Escalation cooldown active (last: %s ago), skipping score change",
			time.Since(lastEscalation).Round(time.Second))
		return
	}

	// 1. Immediately enter black-hole network state
	if err := throttler.ApplyNetworkProfile(throttler.ProfileBlackHole); err != nil {
		log.Printf("Anti-Tamper: Failed to apply black-hole: %v", err)
	} else {
		log.Println("Anti-Tamper: Network set to BLACK-HOLE")
	}

	// 2. Double the current failure score (capped).
	cs, err := penance.LoadComplianceStatus()
	if err != nil {
		log.Printf("Anti-Tamper: Could not load compliance for escalation: %v", err)
		return
	}

	previousScore := cs.FailureScore
	if cs.FailureScore == 0 {
		cs.FailureScore = 50 // Minimum penalty
	} else {
		cs.FailureScore *= 2
	}
	if cs.FailureScore > MaxFailureScore {
		cs.FailureScore = MaxFailureScore
	}
	cs.Locked = true
	cs.TaskStatus = "failed"

	if err := penance.SaveComplianceStatus(cs); err != nil {
		log.Printf("Anti-Tamper: Could not save escalated compliance: %v", err)
	}

	lastEscalation = time.Now()
	log.Printf("Anti-Tamper: Failure score DOUBLED: %d -> %d (cap: %d)",
		previousScore, cs.FailureScore, MaxFailureScore)
}

// periodicMonitor runs integrity checks on a regular interval
func periodicMonitor() {
	ticker := time.NewTicker(CheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		if err := RunAllChecks(); err != nil {
			log.Printf("Anti-Tamper: Periodic check failed: %v", err)
		}
	}
}
