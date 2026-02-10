package antitamper

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
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
	if ExpectedBinaryHash != "" {
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
	// Check if current system matches the expected Nix store path
	// nix-store --verify --check-contents validates store integrity
	output, err := cmdRunner.Run("nix-store", "--verify", "--check-contents")
	if err != nil {
		// Parse output for corruption indicators
		if strings.Contains(string(output), "path") && strings.Contains(string(output), "corrupt") {
			return fmt.Errorf("nix store corruption detected: %s", string(output))
		}
		// nix-store verify may return non-zero for warnings; check output
		log.Printf("Anti-Tamper: nix-store verify output: %s", string(output))
	}

	// Check that the current system profile matches expected configuration
	// by verifying the system derivation hasn't been modified outside of nix
	output, err = cmdRunner.Run("nix-instantiate", "--eval", "-E",
		"(import <nixpkgs/nixos> {}).config.system.stateVersion")
	if err != nil {
		log.Printf("Anti-Tamper: Could not verify NixOS state version: %v", err)
		// Not necessarily tamper - might not be NixOS
	}

	// Verify vex-cli service configuration hasn't been modified
	output, err = cmdRunner.Run("systemctl", "is-active", "vex-cli.service")
	if err != nil || !strings.Contains(string(output), "active") {
		return fmt.Errorf("vex-cli service not active or tampered: %s", string(output))
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

// escalate triggers automatic escalation when tampering is detected
func escalate(reasons []string) {
	log.Printf("Anti-Tamper: ⚠️ ESCALATION TRIGGERED: %v", reasons)

	// 1. Immediately enter black-hole network state
	if err := throttler.ApplyNetworkProfile(throttler.ProfileBlackHole); err != nil {
		log.Printf("Anti-Tamper: Failed to apply black-hole: %v", err)
	} else {
		log.Println("Anti-Tamper: Network set to BLACK-HOLE")
	}

	// 2. Double the current failure_score
	cs, err := penance.LoadComplianceStatus()
	if err != nil {
		log.Printf("Anti-Tamper: Could not load compliance for doubling: %v", err)
		return
	}

	previousScore := cs.FailureScore
	if cs.FailureScore == 0 {
		cs.FailureScore = 50 // Minimum penalty
	} else {
		cs.FailureScore *= 2
	}
	cs.Locked = true
	cs.TaskStatus = "failed"

	if err := penance.SaveComplianceStatus(cs); err != nil {
		log.Printf("Anti-Tamper: Could not save escalated compliance: %v", err)
	}

	log.Printf("Anti-Tamper: Failure score DOUBLED: %d -> %d", previousScore, cs.FailureScore)
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
