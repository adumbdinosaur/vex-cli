package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/adumbdinosaur/vex-cli/internal/antitamper"
	"github.com/adumbdinosaur/vex-cli/internal/guardian"
	vexlog "github.com/adumbdinosaur/vex-cli/internal/logging"
	"github.com/adumbdinosaur/vex-cli/internal/penance"
	"github.com/adumbdinosaur/vex-cli/internal/security"
	"github.com/adumbdinosaur/vex-cli/internal/surveillance"
	"github.com/adumbdinosaur/vex-cli/internal/throttler"
)

func main() {
	// Initialize structured logging first
	if err := vexlog.Init(); err != nil {
		log.Printf("Logging initialization warning: %v", err)
	}
	defer vexlog.Close()

	log.Println("Starting VEX-CLI (Protocol 106-V)...")

	if os.Geteuid() != 0 {
		log.Fatal("Error: VEX-CLI must be run as root.")
	}

	// Load cryptographic management key
	if err := security.Init(); err != nil {
		log.Printf("Security initialization warning: %v", err)
	}

	// Parse CLI commands
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	vexlog.LogCommand(command, strings.Join(os.Args[2:], " "), getComplianceState())

	// Check if this is a restriction-lowering command that requires signing
	if security.IsRestrictionLoweringCommand(command) {
		if len(os.Args) < 3 {
			log.Fatal("Restricted commands require a signed authorization payload (JSON)")
		}
		signedData := []byte(os.Args[2])
		cmd, err := security.ParseSignedCommand(signedData)
		if err != nil {
			log.Fatalf("Invalid signed command: %v", err)
		}
		if err := security.VerifyCommand(cmd); err != nil {
			log.Fatalf("AUTHORIZATION DENIED: %v", err)
		}
	}

	switch command {
	case "init":
		cmdInit()
	case "status":
		cmdStatus()
	case "penance":
		cmdPenance()
	case "throttle":
		if len(os.Args) < 3 {
			log.Fatal("Usage: vex-cli throttle <profile>")
		}
		cmdThrottle(os.Args[2])
	case "block":
		cmdBlock()
	case "unlock":
		cmdUnlock()
	case "check":
		cmdCheck()
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("VEX-CLI (Protocol 106-V) - Administration Interface")
	fmt.Println()
	fmt.Println("Usage: vex-cli <command> [args]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  init       Initialize all subsystems and enforce penance state")
	fmt.Println("  status     Display current compliance, throttle, and surveillance status")
	fmt.Println("  penance    Start interactive penance submission session")
	fmt.Println("  throttle   Set network throttle profile (standard|choke|dial-up|black-hole)")
	fmt.Println("  block      Show active blocks and guardian status")
	fmt.Println("  unlock     Lift restrictions (requires signed authorization)")
	fmt.Println("  check      Run anti-tamper and integrity checks")
}

// -- Commands --

func cmdInit() {
	log.Println("Initializing all subsystems...")

	if err := throttler.Init(); err != nil {
		log.Printf("Throttler initialization warning: %v", err)
	}

	if err := guardian.Init(); err != nil {
		log.Printf("Guardian initialization warning: %v", err)
	}

	if err := surveillance.Init(); err != nil {
		log.Printf("Surveillance initialization warning: %v", err)
	}

	if err := penance.Init(); err != nil {
		log.Printf("Penance initialization warning: %v", err)
	}

	if err := antitamper.Init(); err != nil {
		log.Printf("Anti-tamper initialization warning: %v", err)
	}

	log.Println("All subsystems initialized. Entering monitoring mode...")

	// Block forever in daemon mode
	select {}
}

func cmdStatus() {
	start := time.Now()

	fmt.Println("========================================")
	fmt.Println("VEX-CLI STATUS REPORT")
	fmt.Printf("Time: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Println("========================================")

	// Compliance Status
	cs, err := penance.LoadComplianceStatus()
	if err != nil {
		fmt.Printf("Compliance: ERROR loading status: %v\n", err)
	} else {
		fmt.Println()
		fmt.Println("[COMPLIANCE]")
		fmt.Printf("  Failure Score:  %d\n", cs.FailureScore)
		fmt.Printf("  Task Status:    %s\n", cs.TaskStatus)
		fmt.Printf("  System Locked:  %v\n", cs.Locked)
		fmt.Printf("  Total Failures: %d\n", cs.TotalFailures)
		fmt.Printf("  Total Completed:%d\n", cs.TotalCompleted)
		fmt.Printf("  Last Updated:   %s\n", cs.LastUpdated)
	}

	// Manifest Info
	m, err := penance.LoadManifest("penance-manifest.json")
	if err == nil {
		fmt.Println()
		fmt.Println("[ACTIVE PENANCE]")
		fmt.Printf("  Task ID: %s\n", m.Active.TaskID)
		fmt.Printf("  Type:    %s\n", m.Active.Type)
		fmt.Printf("  Topic:   %s\n", m.Active.RequiredContent.Topic)
		fmt.Printf("  Min Words: %d\n", m.Active.RequiredContent.MinWordCount)
		fmt.Printf("  Network Profile: %s\n", m.Overrides.Network.Profile)
		fmt.Printf("  CPU Limit: %d%%\n", m.Overrides.Compute.CPULimit)
		fmt.Printf("  Input Latency: %dms\n", m.Overrides.Compute.InputLatency)
	}

	// Surveillance Metrics
	fmt.Println()
	fmt.Println("[SURVEILLANCE]")
	kpm := surveillance.GetCurrentKPM()
	keystrokes, lines := surveillance.GetMetricSnapshot()
	fmt.Printf("  Keystrokes: %d\n", keystrokes)
	fmt.Printf("  KPM:        %.2f\n", kpm)
	fmt.Printf("  Lines:      %d\n", lines)

	elapsed := time.Since(start)
	fmt.Println()
	fmt.Printf("Status check completed in %v\n", elapsed)
	fmt.Println("========================================")
}

func cmdPenance() {
	// Initialize required subsystems
	if err := throttler.Init(); err != nil {
		log.Printf("Throttler initialization warning: %v", err)
	}
	if err := surveillance.Init(); err != nil {
		log.Printf("Surveillance initialization warning: %v", err)
	}
	if err := penance.Init(); err != nil {
		log.Fatalf("Penance initialization failed: %v", err)
	}

	manifest := penance.CurrentManifest
	if manifest == nil {
		log.Fatal("No manifest loaded. Exiting.")
	}

	fmt.Println("\n========================================")
	fmt.Printf("VEXATION PROTOCOL ACTIVE\n")
	fmt.Printf("Subject: %s\n", manifest.Meta.TargetID)
	fmt.Printf("Violation Level: %s\n", manifest.Active.Type)
	fmt.Println("========================================")
	fmt.Printf("INSTRUCTIONS:\n")
	fmt.Printf("Topic: %s\n", manifest.Active.RequiredContent.Topic)
	fmt.Printf("Minimum Word Count: %d\n", manifest.Active.RequiredContent.MinWordCount)
	if len(manifest.Active.RequiredContent.ValidationStrings) > 0 {
		fmt.Printf("Must include phrases: %v\n", manifest.Active.RequiredContent.ValidationStrings)
	}
	if !manifest.Active.Constraints.AllowBackspace {
		fmt.Println("WARNING: Backspace is DISABLED. Errors require full line reset.")
	}
	if manifest.Active.Constraints.EnforceRhythm {
		fmt.Printf("Typing speed: %d-%d KPM enforced\n",
			manifest.Active.Constraints.MinKPM, manifest.Active.Constraints.MaxKPM)
	}
	fmt.Println("----------------------------------------")
	fmt.Println("Type your submission below. Press Ctrl+D (EOF) when finished.")
	fmt.Println("----------------------------------------")

	scanner := bufio.NewScanner(os.Stdin)
	var sb strings.Builder

	for scanner.Scan() {
		line := scanner.Text()

		// Enforce allow_backspace: false constraint
		if !penance.ValidateLineInput(line, manifest.Active.Constraints) {
			fmt.Println("[ERROR] Backspace detected! Line REJECTED. Retype the entire line.")
			_ = penance.RecordFailure("backspace_violation")
			continue
		}

		sb.WriteString(line + "\n")
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading input: %v", err)
		return
	}

	submission := sb.String()
	verifySubmission(submission, manifest)
}

func verifySubmission(text string, m *penance.Manifest) {
	fmt.Println("\nVerifying submission...")
	time.Sleep(1 * time.Second) // Dramatic pause

	result := penance.ValidateSubmission(text, m)

	if !result.Valid {
		for _, e := range result.Errors {
			fmt.Printf("[FAIL] %s\n", e)
		}
		fmt.Println("\nSubmission REJECTED. Penance continues.")
		_ = penance.RecordFailure("submission_rejected")
		os.Exit(1)
	}

	fmt.Println("\nSubmission ACCEPTED.")
	_ = penance.RecordCompletion()
	liftRestrictions()
}

func cmdThrottle(profile string) {
	if err := throttler.Init(); err != nil {
		log.Fatalf("Throttler init failed: %v", err)
	}

	p := throttler.Profile(profile)
	if err := throttler.ApplyNetworkProfile(p); err != nil {
		log.Fatalf("Failed to apply profile '%s': %v", profile, err)
	}
	fmt.Printf("Network profile set to: %s\n", profile)
}

func cmdBlock() {
	fmt.Println("[GUARDIAN STATUS]")
	fmt.Println("  Process Reaper: Active")
	fmt.Println("  OOM Shield: Engaged (-1000)")

	// Load and display forbidden apps
	data, err := os.ReadFile("forbidden-apps.json")
	if err == nil {
		var config struct {
			Apps []string `json:"forbidden_apps"`
		}
		if json.Unmarshal(data, &config) == nil {
			fmt.Printf("  Forbidden Apps: %v\n", config.Apps)
		}
	}

	fmt.Println("  SNI Filtering: Active")
}

func cmdUnlock() {
	fmt.Println("Lifting restrictions (authorized)...")
	liftRestrictions()
}

func cmdCheck() {
	fmt.Println("Running integrity checks...")
	if err := antitamper.RunAllChecks(); err != nil {
		fmt.Printf("INTEGRITY CHECK FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("All integrity checks PASSED.")
}

func liftRestrictions() {
	fmt.Println("Lifting restrictions...")

	if err := throttler.Init(); err != nil {
		log.Printf("Throttler init: %v", err)
	}

	if err := throttler.ApplyNetworkProfile(throttler.ProfileStandard); err != nil {
		log.Printf("Failed to restore network: %v", err)
	}

	if err := guardian.SetOOMScore(0); err != nil {
		log.Printf("Failed to restore OOM score: %v", err)
	}

	if err := surveillance.InjectLatency(0); err != nil {
		log.Printf("Failed to remove latency: %v", err)
	}

	fmt.Println("System state normalized. You may proceed.")
}

func getComplianceState() string {
	cs, err := penance.LoadComplianceStatus()
	if err != nil {
		return "unknown"
	}
	return fmt.Sprintf("score=%d,status=%s,locked=%v", cs.FailureScore, cs.TaskStatus, cs.Locked)
}
