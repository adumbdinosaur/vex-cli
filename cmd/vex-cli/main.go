// vex-cli is the thin control-plane client for the vexd daemon.
// It translates CLI arguments into IPC requests, sends them to
// the daemon over a Unix socket, and prints the response.
//
// The daemon (vexd) owns all subsystems and persisted state.
// Running "vex-cli throttle black-hole" while vexd is running
// modifies the live daemon AND persists for next boot.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/adumbdinosaur/vex-cli/internal/ipc"
	vexlog "github.com/adumbdinosaur/vex-cli/internal/logging"
	"github.com/adumbdinosaur/vex-cli/internal/penance"
	"github.com/adumbdinosaur/vex-cli/internal/security"
	"github.com/adumbdinosaur/vex-cli/internal/surveillance"
)

func main() {
	if err := vexlog.Init(); err != nil {
		log.Printf("Logging initialization warning: %v", err)
	}
	defer vexlog.Close()

	// Allow non-root users in the 'vex' group or root user
	if !canAccessVex() {
		log.Fatal("Error: vex-cli requires root privileges or membership in the 'vex' group.")
	}

	if err := security.Init(); err != nil {
		log.Printf("Security initialization warning: %v", err)
	}

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	vexlog.LogCommand(command, strings.Join(os.Args[2:], " "), getComplianceState())

	// Authorization gate for restriction-lowering commands
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
	case "status":
		cmdStatus()
	case "throttle":
		if len(os.Args) < 3 {
			log.Fatal("Usage: vex-cli throttle <profile>")
		}
		cmdThrottle(os.Args[2])
	case "cpu":
		if len(os.Args) < 3 {
			log.Fatal("Usage: vex-cli cpu <percent>")
		}
		cmdCPU(os.Args[2])
	case "latency":
		if len(os.Args) < 3 {
			log.Fatal("Usage: vex-cli latency <ms>")
		}
		cmdLatency(os.Args[2])
	case "oom":
		if len(os.Args) < 3 {
			log.Fatal("Usage: vex-cli oom <score>")
		}
		cmdOOM(os.Args[2])
	case "penance":
		cmdPenance()
	case "block":
		if len(os.Args) < 3 {
			cmdBlockList()
			return
		}
		switch os.Args[2] {
		case "add":
			if len(os.Args) < 4 {
				log.Fatal("Usage: vex-cli block add <domain>")
			}
			cmdBlockAdd(os.Args[3])
		case "rm", "remove", "del":
			if len(os.Args) < 4 {
				log.Fatal("Usage: vex-cli block rm <domain>")
			}
			cmdBlockRemove(os.Args[3])
		case "list", "ls":
			cmdBlockList()
		default:
			// Treat as "block add <domain>" shorthand
			cmdBlockAdd(os.Args[2])
		}
	case "unlock":
		cmdUnlock()
	case "reset-score":
		cmdResetScore()
	case "state":
		cmdState()
	case "check":
		cmdCheck()
	case "lines":
		if len(os.Args) < 3 {
			cmdLinesStatus()
			return
		}
		switch os.Args[2] {
		case "set":
			// vex-cli lines set <count> <phrase...>
			if len(os.Args) < 5 {
				log.Fatal("Usage: vex-cli lines set <count> <phrase>")
			}
			cmdLinesSet(os.Args[3], strings.Join(os.Args[4:], " "))
		case "clear", "cancel":
			cmdLinesClear()
		case "status":
			cmdLinesStatus()
		case "submit":
			cmdLinesSubmitInteractive()
		default:
			fmt.Printf("Unknown lines subcommand: %s\n", os.Args[2])
			os.Exit(1)
		}
	case "app":
		if len(os.Args) < 3 {
			cmdAppList()
			return
		}
		switch os.Args[2] {
		case "add":
			if len(os.Args) < 4 {
				log.Fatal("Usage: vex-cli app add <name>")
			}
			cmdAppAdd(os.Args[3])
		case "rm", "remove", "del":
			if len(os.Args) < 4 {
				log.Fatal("Usage: vex-cli app rm <name>")
			}
			cmdAppRemove(os.Args[3])
		case "list", "ls":
			cmdAppList()
		default:
			fmt.Printf("Unknown app subcommand: %s\n", os.Args[2])
			os.Exit(1)
		}
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("VEX-CLI (Protocol 106-V) - Control Plane")
	fmt.Println()
	fmt.Println("Usage: vex-cli <command> [args]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  status       Display current system state (human-readable)")
	fmt.Println("  state        Dump live system state as JSON (machine-readable)")
	fmt.Println("  throttle     Set network profile (standard|choke|dial-up|black-hole|blackout)")
	fmt.Println("  cpu          Set CPU limit percentage (0-100)")
	fmt.Println("  latency      Set input latency in milliseconds")
	fmt.Println("  oom          Set OOM score adjustment (-1000 to 1000)")
	fmt.Println("  penance      Start interactive penance submission session")
	fmt.Println("  block        Manage SNI domain blocklist:")
	fmt.Println("    block add <domain>    Add a domain to the firewall blocklist")
	fmt.Println("    block rm <domain>     Remove a domain from the blocklist")
	fmt.Println("    block list            List currently blocked domains")
	fmt.Println("    block <domain>        Shorthand for 'block add <domain>'")
	fmt.Println("  lines        Manage writing-lines task:")
	fmt.Println("    lines set <N> <phrase> Assign phrase to be written N times")
	fmt.Println("    lines status           Show progress")
	fmt.Println("    lines submit           Interactive submission (type lines)")
	fmt.Println("    lines clear            Cancel the active task")
	fmt.Println("  app          Manage forbidden apps (process blocklist):")
	fmt.Println("    app add <name>         Add an app to the forbidden list")
	fmt.Println("    app rm <name>          Remove an app from the forbidden list")
	fmt.Println("    app list               List currently forbidden apps")
	fmt.Println("  reset-score  Reset failure score to zero (requires signed authorization)")
	fmt.Println("  unlock       Lift all restrictions (requires signed authorization)")
	fmt.Println("  check        Run anti-tamper and integrity checks")
	fmt.Println()
	fmt.Println("All commands talk to the running vexd daemon and persist for next boot.")
}

// ── Helpers ─────────────────────────────────────────────────────────

func client() *ipc.Client { return ipc.NewClient() }

func sendOrDie(req *ipc.Request) *ipc.Response {
	resp, err := client().Send(req)
	if err != nil {
		log.Fatalf("Failed to communicate with vexd: %v", err)
	}
	if !resp.OK {
		log.Fatalf("Command failed: %s", resp.Error)
	}
	return resp
}

// ── Command implementations ─────────────────────────────────────────

func cmdState() {
	resp, err := client().Send(&ipc.Request{Command: ipc.CmdState})
	if err != nil {
		log.Fatalf("Failed to communicate with vexd: %v", err)
	}
	if !resp.OK {
		log.Fatalf("Command failed: %s", resp.Error)
	}
	out, _ := json.MarshalIndent(resp.State, "", "  ")
	fmt.Println(string(out))
}

func cmdStatus() {
	resp := sendOrDie(&ipc.Request{Command: ipc.CmdStatus})
	s := resp.State

	fmt.Println("========================================")
	fmt.Println("VEX-CLI STATUS REPORT")
	fmt.Printf("Time: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Println("========================================")

	fmt.Println()
	fmt.Println("[COMPLIANCE]")
	fmt.Printf("  System Locked:  %v\n", s.Compliance.Locked)
	fmt.Printf("  Failure Score:  %d\n", s.Compliance.FailureScore)
	fmt.Printf("  Task Status:    %s\n", s.Compliance.TaskStatus)
	if s.Writing.Active {
		fmt.Printf("  Lines Done:     %d / %d\n", s.Writing.Completed, s.Writing.Required)
	}

	fmt.Println()
	fmt.Println("[NETWORK]")
	fmt.Printf("  Profile:      %s\n", s.Network.Profile)
	fmt.Printf("  Packet Loss:  %.2f%%\n", s.Network.PacketLossPct)

	fmt.Println()
	fmt.Println("[COMPUTE]")
	fmt.Printf("  CPU Limit:      %d%%\n", s.Compute.CPULimitPct)
	fmt.Printf("  OOM Score Adj:  %d\n", s.Compute.OOMScoreAdj)
	fmt.Printf("  Input Latency:  %dms\n", s.Compute.InputLatencyMs)

	fmt.Println()
	fmt.Println("[GUARDIAN]")
	fmt.Printf("  Firewall: %v\n", s.Guardian.FirewallEnabled)
	fmt.Printf("  Reaper:   %v\n", s.Guardian.ReaperEnabled)
	if len(s.Guardian.BlockedDomains) > 0 {
		fmt.Printf("  Blocked:  %d domains\n", len(s.Guardian.BlockedDomains))
		for _, d := range s.Guardian.BlockedDomains {
			fmt.Printf("            - %s\n", d)
		}
	}

	if s.Writing.Active {
		fmt.Println()
		fmt.Println("[WRITING TASK]")
		fmt.Printf("  Phrase:    %q\n", s.Writing.Phrase)
		fmt.Printf("  Progress:  %d / %d\n", s.Writing.Completed, s.Writing.Required)
		fmt.Printf("  Remaining: %d\n", s.Writing.Required-s.Writing.Completed)
	}

	fmt.Println()
	fmt.Printf("State last updated: %s (by: %s)\n", s.LastUpdated, s.ChangedBy)
	fmt.Println("========================================")
}

func cmdThrottle(profile string) {
	resp := sendOrDie(&ipc.Request{
		Command: ipc.CmdThrottle,
		Args:    map[string]string{"profile": profile},
	})
	fmt.Println(resp.Message)
}

func cmdCPU(pct string) {
	resp := sendOrDie(&ipc.Request{
		Command: ipc.CmdCPU,
		Args:    map[string]string{"percent": pct},
	})
	fmt.Println(resp.Message)
}

func cmdLatency(ms string) {
	resp := sendOrDie(&ipc.Request{
		Command: ipc.CmdLatency,
		Args:    map[string]string{"ms": ms},
	})
	fmt.Println(resp.Message)
}

func cmdOOM(score string) {
	resp := sendOrDie(&ipc.Request{
		Command: ipc.CmdOOM,
		Args:    map[string]string{"score": score},
	})
	fmt.Println(resp.Message)
}

func cmdPenance() {
	// Penance is interactive (stdin) so we handle it locally
	// but validate + report result to daemon.
	//
	// NOTE: surveillance.Init() is only useful when running as root
	// (it opens /dev/input/* devices).  When running as a non-root vex
	// group member, skip it to avoid noisy "permission denied" warnings
	// that obscure the penance interface.
	if os.Geteuid() == 0 {
		if err := surveillance.Init(); err != nil {
			log.Printf("Surveillance initialization warning: %v", err)
		}
	}

	m, err := penance.LoadManifest(penance.ManifestFile)
	if err != nil {
		log.Fatalf("Failed to load penance manifest: %v", err)
	}

	fmt.Println("\n========================================")
	fmt.Printf("VEXATION PROTOCOL ACTIVE\n")
	fmt.Printf("Subject: %s\n", m.Meta.TargetID)
	fmt.Printf("Violation Level: %s\n", m.Active.Type)
	fmt.Println("========================================")
	fmt.Printf("INSTRUCTIONS:\n")
	fmt.Printf("Topic: %s\n", m.Active.RequiredContent.Topic)
	fmt.Printf("Minimum Word Count: %d\n", m.Active.RequiredContent.MinWordCount)
	if len(m.Active.RequiredContent.ValidationStrings) > 0 {
		fmt.Printf("Must include phrases: %v\n", m.Active.RequiredContent.ValidationStrings)
	}
	if !m.Active.Constraints.AllowBackspace {
		fmt.Println("WARNING: Backspace is DISABLED. Errors require full line reset.")
	}
	if m.Active.Constraints.EnforceRhythm {
		fmt.Printf("Typing speed: %d-%d KPM enforced\n",
			m.Active.Constraints.MinKPM, m.Active.Constraints.MaxKPM)
	}
	fmt.Println("----------------------------------------")
	fmt.Println("Type your submission below. Press Ctrl+D (EOF) when finished.")
	fmt.Println("----------------------------------------")

	scanner := bufio.NewScanner(os.Stdin)
	var sb strings.Builder
	lineNum := 0
	totalWords := 0
	for scanner.Scan() {
		line := scanner.Text()
		if !penance.ValidateLineInput(line, m.Active.Constraints) {
			fmt.Println("[ERROR] Backspace detected! Line REJECTED. Retype the entire line.")
			vexlog.LogEvent("PENANCE", "LINE_REJECTED", fmt.Sprintf("reason=backspace_violation line=%d", lineNum+1))
			_ = penance.RecordFailure("backspace_violation")
			continue
		}
		lineNum++
		lineWords := len(strings.Fields(line))
		totalWords += lineWords
		sb.WriteString(line + "\n")

		// Show the user that each line is registered
		fmt.Printf("  [line %d] %d words (total: %d/%d)\n",
			lineNum, lineWords, totalWords, m.Active.RequiredContent.MinWordCount)

		vexlog.LogEvent("PENANCE", "LINE_ACCEPTED", fmt.Sprintf("line=%d words=%d total_words=%d", lineNum, lineWords, totalWords))

		// Send each accepted line to the daemon so it is registered in the
		// daemon log and tracked over the socket.
		resp, err := client().Send(&ipc.Request{
			Command: ipc.CmdPenanceInput,
			Args:    map[string]string{"line": line, "num": strconv.Itoa(lineNum)},
		})
		if err != nil {
			// Non-fatal: log locally but don't interrupt the session
			vexlog.LogEvent("PENANCE", "IPC_WARN", fmt.Sprintf("could not reach daemon: %v", err))
		} else if resp != nil && !resp.OK {
			vexlog.LogEvent("PENANCE", "IPC_WARN", fmt.Sprintf("daemon rejected input: %s", resp.Error))
		}

		_ = penance.MarkInProgress()
	}
	if err := scanner.Err(); err != nil {
		log.Printf("Error reading input: %v", err)
		return
	}

	submission := sb.String()
	fmt.Println("\nVerifying submission...")
	time.Sleep(1 * time.Second)

	result := penance.ValidateSubmission(submission, m)
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

	// Tell the daemon to lift restrictions
	sendOrDie(&ipc.Request{Command: ipc.CmdUnlock})
	fmt.Println("System state normalized. You may proceed.")
}

func cmdBlockAdd(domain string) {
	resp := sendOrDie(&ipc.Request{
		Command: ipc.CmdBlockAdd,
		Args:    map[string]string{"domain": domain},
	})
	fmt.Println(resp.Message)
}

func cmdBlockRemove(domain string) {
	resp := sendOrDie(&ipc.Request{
		Command: ipc.CmdBlockRemove,
		Args:    map[string]string{"domain": domain},
	})
	fmt.Println(resp.Message)
}

func cmdBlockList() {
	resp := sendOrDie(&ipc.Request{Command: ipc.CmdBlockList})
	s := resp.State

	fmt.Println("[GUARDIAN — BLOCKED DOMAINS]")
	fmt.Printf("  Firewall Enabled: %v\n", s.Guardian.FirewallEnabled)
	fmt.Printf("  Process Reaper:   %v\n", s.Guardian.ReaperEnabled)
	fmt.Println()
	if len(s.Guardian.BlockedDomains) == 0 {
		fmt.Println("  (no domains blocked)")
	} else {
		for i, d := range s.Guardian.BlockedDomains {
			fmt.Printf("  %d. %s\n", i+1, d)
		}
		fmt.Printf("\n  Total: %d domains\n", len(s.Guardian.BlockedDomains))
	}
}

func cmdResetScore() {
	fmt.Println("Resetting failure score (authorized)…")
	resp := sendOrDie(&ipc.Request{Command: ipc.CmdResetScore})
	fmt.Println(resp.Message)
}

func cmdAppAdd(app string) {
	resp := sendOrDie(&ipc.Request{
		Command: ipc.CmdAppAdd,
		Args:    map[string]string{"app": app},
	})
	fmt.Println(resp.Message)
}

func cmdAppRemove(app string) {
	resp := sendOrDie(&ipc.Request{
		Command: ipc.CmdAppRemove,
		Args:    map[string]string{"app": app},
	})
	fmt.Println(resp.Message)
}

func cmdAppList() {
	resp := sendOrDie(&ipc.Request{Command: ipc.CmdAppList})

	fmt.Println("[GUARDIAN — FORBIDDEN APPS]")
	if resp.Message == "" {
		fmt.Println("  (no forbidden apps)")
	} else {
		apps := strings.Split(resp.Message, ",")
		for i, a := range apps {
			fmt.Printf("  %d. %s\n", i+1, a)
		}
		fmt.Printf("\n  Total: %d apps\n", len(apps))
	}
}

func cmdUnlock() {
	fmt.Println("Lifting restrictions (authorized)…")
	resp := sendOrDie(&ipc.Request{Command: ipc.CmdUnlock})
	fmt.Println(resp.Message)
}

func cmdCheck() {
	resp := sendOrDie(&ipc.Request{Command: ipc.CmdCheck})
	fmt.Println(resp.Message)
}

func getComplianceState() string {
	cs, err := penance.LoadComplianceStatus()
	if err != nil {
		return "unknown"
	}
	return fmt.Sprintf("score=%d,status=%s,locked=%v", cs.FailureScore, cs.TaskStatus, cs.Locked)
}

// ── Writing-lines CLI commands ──────────────────────────────────────

func cmdLinesSet(countStr, phrase string) {
	resp := sendOrDie(&ipc.Request{
		Command: ipc.CmdLinesSet,
		Args:    map[string]string{"phrase": phrase, "count": countStr},
	})
	fmt.Println(resp.Message)
}

func cmdLinesClear() {
	resp := sendOrDie(&ipc.Request{Command: ipc.CmdLinesClear})
	fmt.Println(resp.Message)
}

func cmdLinesStatus() {
	resp := sendOrDie(&ipc.Request{Command: ipc.CmdLinesStatus})
	s := resp.State

	if !s.Writing.Active {
		fmt.Println("No active writing task.")
		return
	}

	remaining := s.Writing.Required - s.Writing.Completed
	fmt.Println("[WRITING TASK]")
	fmt.Printf("  Phrase:    %q\n", s.Writing.Phrase)
	fmt.Printf("  Progress:  %d / %d\n", s.Writing.Completed, s.Writing.Required)
	fmt.Printf("  Remaining: %d\n", remaining)
}

func cmdLinesSubmitInteractive() {
	// First, check if there's an active task
	statusResp := sendOrDie(&ipc.Request{Command: ipc.CmdLinesStatus})
	s := statusResp.State
	if !s.Writing.Active {
		fmt.Println("No active writing task.")
		return
	}

	remaining := s.Writing.Required - s.Writing.Completed
	fmt.Println("========================================")
	fmt.Println("WRITING LINES — DISCIPLINARY PROTOCOL")
	fmt.Println("========================================")
	fmt.Printf("Phrase:    %q\n", s.Writing.Phrase)
	fmt.Printf("Remaining: %d lines\n", remaining)
	fmt.Println("----------------------------------------")
	fmt.Println("Type the exact phrase on each line. Ctrl+D to stop.")
	fmt.Println("----------------------------------------")

	scanner := bufio.NewScanner(os.Stdin)
	accepted := 0
	rejected := 0
	for scanner.Scan() {
		line := scanner.Text()
		resp, err := client().Send(&ipc.Request{
			Command: ipc.CmdLinesSubmit,
			Args:    map[string]string{"line": line},
		})
		if err != nil {
			log.Fatalf("Failed to communicate with vexd: %v", err)
		}
		if resp.OK {
			accepted++
			fmt.Printf("  ✓ %s\n", resp.Message)
			// Check if task is now complete
			if resp.State != nil && !resp.State.Writing.Active {
				fmt.Println("\n" + resp.Message)
				break
			}
		} else {
			rejected++
			fmt.Printf("  ✗ REJECTED: %s\n", resp.Error)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading input: %v", err)
	}

	fmt.Printf("\nSession: %d accepted, %d rejected\n", accepted, rejected)
}

// canAccessVex checks if the current user has permission to run vex-cli.
// Returns true if the user is root OR is a member of the 'vex' group.
func canAccessVex() bool {
	// Root always has access
	if os.Geteuid() == 0 {
		return true
	}

	// Check if user is in the 'vex' group
	groups, err := os.Getgroups()
	if err != nil {
		return false
	}

	// Look up the 'vex' group GID
	vexGroup, err := user.LookupGroup("vex")
	if err != nil {
		// Group doesn't exist, only root can access
		return false
	}

	vexGid, err := strconv.Atoi(vexGroup.Gid)
	if err != nil {
		return false
	}

	// Check if any of the user's groups match 'vex'
	for _, gid := range groups {
		if gid == vexGid {
			return true
		}
	}

	return false
}

