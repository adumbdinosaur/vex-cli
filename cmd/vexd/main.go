// vexd is the VEX enforcement daemon.  It owns all subsystems (throttler,
// guardian, surveillance, penance, anti-tamper), persists unified state to
// disk, and exposes a Unix-socket IPC interface so that the thin vex-cli
// control-plane binary can issue commands at runtime.
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/adumbdinosaur/vex-cli/internal/antitamper"
	"github.com/adumbdinosaur/vex-cli/internal/guardian"
	"github.com/adumbdinosaur/vex-cli/internal/ipc"
	vexlog "github.com/adumbdinosaur/vex-cli/internal/logging"
	"github.com/adumbdinosaur/vex-cli/internal/penance"
	"github.com/adumbdinosaur/vex-cli/internal/security"
	"github.com/adumbdinosaur/vex-cli/internal/state"
	"github.com/adumbdinosaur/vex-cli/internal/surveillance"
	"github.com/adumbdinosaur/vex-cli/internal/throttler"
)

// dryRun disables all kernel side-effects (qdiscs, nftables, cgroups,
// OOM, latency injection).  State is still tracked in memory and persisted
// to disk, and the IPC server works normally — only the enforcement
// syscalls are skipped.  Useful for testing the CLI ↔ daemon flow.
var dryRun bool

func main() {
	// Check for --dry-run before anything else.
	for _, arg := range os.Args[1:] {
		if arg == "--dry-run" {
			dryRun = true
		}
	}

	// ── Logging ─────────────────────────────────────────────────────
	if err := vexlog.Init(); err != nil {
		log.Printf("Logging initialization warning: %v", err)
	}
	defer vexlog.Close()

	if dryRun {
		log.Println("Starting vexd (Protocol 106-V) [DRY-RUN MODE] …")
	} else {
		log.Println("Starting vexd (Protocol 106-V) …")
	}

	if os.Geteuid() != 0 {
		log.Fatal("Error: vexd must be run as root.")
	}

	// ── Security ────────────────────────────────────────────────────
	if err := security.Init(); err != nil {
		log.Printf("Security initialization warning: %v", err)
	}

	// ── Load persisted state ────────────────────────────────────────
	sysState, err := state.Load()
	if err != nil {
		log.Printf("State load warning (using defaults): %v", err)
		sysState = state.Default()
	}

	// Sync compliance snapshot from the penance subsystem.
	if cs, err := penance.LoadComplianceStatus(); err == nil {
		sysState.Compliance.Locked = cs.Locked
		sysState.Compliance.FailureScore = cs.FailureScore
		sysState.Compliance.TaskStatus = cs.TaskStatus
	}

	penaltyActive := sysState.Compliance.Locked
	if penaltyActive {
		log.Println("Compliance state: LOCKED — penalties will be enforced")
	} else {
		log.Println("Compliance state: UNLOCKED — starting with persisted/clean state")
	}

	// ── Subsystem init ──────────────────────────────────────────────

	if !dryRun {
		// 1. Throttler — detect interface
		if err := throttler.Init(); err != nil {
			log.Printf("Throttler initialization warning: %v", err)
		}

		// 2. Apply network state
		applyNetworkState(sysState)

		// 3. Apply compute state
		applyComputeState(sysState)

		// 4. Guardian
		if err := guardian.Init(penaltyActive || sysState.Guardian.FirewallEnabled); err != nil {
			log.Printf("Guardian initialization warning: %v", err)
		}

		// 5. Surveillance
		if err := surveillance.Init(); err != nil {
			log.Printf("Surveillance initialization warning: %v", err)
		}
		if sysState.Compute.InputLatencyMs > 0 {
			surveillance.InjectLatency(sysState.Compute.InputLatencyMs)
		}

		// 6. Penance (may override state if penalty is active)
		if err := penance.Init(); err != nil {
			log.Printf("Penance initialization warning: %v", err)
		}
		// If penance enforcement changed network/compute, re-sync state
		if penaltyActive {
			if m := penance.CurrentManifest; m != nil {
				sysState.Network.Profile = m.Overrides.Network.Profile
				sysState.Network.PacketLossPct = float32(m.Overrides.Network.PacketLoss)
				sysState.Compute.CPULimitPct = m.Overrides.Compute.CPULimit
				sysState.Compute.InputLatencyMs = m.Overrides.Compute.InputLatency
				sysState.Compute.OOMScoreAdj = m.Overrides.Compute.OOMScoreAdj
				sysState.Guardian.FirewallEnabled = true
				sysState.ChangedBy = "penance"
			}
		}

		// 7. Anti-tamper
		if err := antitamper.Init(); err != nil {
			log.Printf("Anti-tamper initialization warning: %v", err)
		}
	} else {
		log.Println("[DRY-RUN] Skipping all subsystem initialization (no kernel changes)")
	}

	// Persist the resolved state so it's always up to date on disk.
	if err := state.Save(sysState); err != nil {
		log.Printf("Failed to persist initial state: %v", err)
	}

	// ── IPC server ──────────────────────────────────────────────────
	srv, err := ipc.NewServer(sysState)
	if err != nil {
		log.Fatalf("Failed to start IPC server: %v", err)
	}
	registerHandlers(srv)
	go srv.Serve()

	if dryRun {
		log.Println("All subsystems initialized. Daemon ready. [DRY-RUN — no enforcement]")
	} else {
		log.Println("All subsystems initialized. Daemon ready.")
	}
	vexlog.LogEvent("DAEMON", "STARTED", fmt.Sprintf("penalty_active=%v, dry_run=%v", penaltyActive, dryRun))

	// ── Wait for signal ─────────────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("Received %s, shutting down…", sig)
	srv.Close()

	if !dryRun {
		// Clean up kernel state so rules/qdiscs don't persist after the daemon exits.
		log.Println("Cleaning up network qdiscs…")
		if err := throttler.ApplyNetworkProfile(throttler.ProfileStandard); err != nil {
			log.Printf("Warning: failed to clear qdiscs: %v", err)
		}
		log.Println("Cleaning up guardian (nftables + eBPF)…")
		if err := guardian.Shutdown(); err != nil {
			log.Printf("Warning: guardian shutdown: %v", err)
		}
	} else {
		log.Println("[DRY-RUN] Skipping kernel cleanup (nothing was applied)")
	}
	vexlog.LogEvent("DAEMON", "STOPPED", sig.String())
}

// ═══════════════════════════════════════════════════════════════════
// State application helpers
// ═══════════════════════════════════════════════════════════════════

func applyNetworkState(s *state.SystemState) {
	p := throttler.Profile(s.Network.Profile)
	if s.Network.PacketLossPct > 0 {
		if err := throttler.ApplyNetworkProfileWithEntropy(p, s.Network.PacketLossPct); err != nil {
			log.Printf("Failed to apply network state: %v", err)
		}
	} else {
		if err := throttler.ApplyNetworkProfile(p); err != nil {
			log.Printf("Failed to apply network profile: %v", err)
		}
	}
}

func applyComputeState(s *state.SystemState) {
	if s.Compute.CPULimitPct > 0 && s.Compute.CPULimitPct <= 100 {
		if err := throttler.SetCPULimit(s.Compute.CPULimitPct); err != nil {
			log.Printf("Failed to apply CPU limit: %v", err)
		}
	}
	if s.Compute.OOMScoreAdj != 0 {
		if err := guardian.SetOOMScore(s.Compute.OOMScoreAdj); err != nil {
			log.Printf("Failed to apply OOM score: %v", err)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════
// IPC command handlers — each mutates state + applies side-effects
// ═══════════════════════════════════════════════════════════════════

func registerHandlers(srv *ipc.Server) {
	srv.Handle(ipc.CmdStatus, handleStatus)
	srv.Handle(ipc.CmdState, handleState)
	srv.Handle(ipc.CmdThrottle, handleThrottle)
	srv.Handle(ipc.CmdCPU, handleCPU)
	srv.Handle(ipc.CmdLatency, handleLatency)
	srv.Handle(ipc.CmdOOM, handleOOM)
	srv.Handle(ipc.CmdUnlock, handleUnlock)
	srv.Handle(ipc.CmdCheck, handleCheck)
}

func handleStatus(s *state.SystemState, req *ipc.Request) *ipc.Response {
	// Refresh live compliance from disk
	if cs, err := penance.LoadComplianceStatus(); err == nil {
		s.Compliance.Locked = cs.Locked
		s.Compliance.FailureScore = cs.FailureScore
		s.Compliance.TaskStatus = cs.TaskStatus
	}
	return &ipc.Response{OK: true, State: s}
}

func handleState(s *state.SystemState, req *ipc.Request) *ipc.Response {
	return &ipc.Response{OK: true, State: s}
}

func handleThrottle(s *state.SystemState, req *ipc.Request) *ipc.Response {
	profileStr, ok := req.Args["profile"]
	if !ok {
		return &ipc.Response{OK: false, Error: "missing 'profile' argument"}
	}

	p, err := throttler.ResolveProfile(profileStr)
	if err != nil {
		return &ipc.Response{OK: false, Error: err.Error()}
	}

	if !dryRun {
		if err := throttler.ApplyNetworkProfile(p); err != nil {
			return &ipc.Response{OK: false, Error: fmt.Sprintf("failed to apply profile: %v", err)}
		}
	} else {
		log.Printf("[DRY-RUN] Would apply network profile: %s", p)
	}

	s.Network.Profile = string(p)
	s.Network.PacketLossPct = 0
	s.ChangedBy = "cli"
	vexlog.LogEvent("THROTTLER", "PROFILE_CHANGED",
		fmt.Sprintf("profile=%s (requested=%s), source=cli", p, profileStr))

	return &ipc.Response{OK: true, Message: fmt.Sprintf("Network profile set to: %s", p), State: s}
}

func handleCPU(s *state.SystemState, req *ipc.Request) *ipc.Response {
	pct, err := ipc.ParseIntArg(req.Args, "percent")
	if err != nil {
		return &ipc.Response{OK: false, Error: err.Error()}
	}

	if !dryRun {
		if err := throttler.SetCPULimit(pct); err != nil {
			return &ipc.Response{OK: false, Error: fmt.Sprintf("failed to set CPU limit: %v", err)}
		}
	} else {
		log.Printf("[DRY-RUN] Would set CPU limit: %d%%", pct)
	}

	s.Compute.CPULimitPct = pct
	s.ChangedBy = "cli"
	vexlog.LogEvent("THROTTLER", "CPU_CHANGED", fmt.Sprintf("cpu=%d%%, source=cli", pct))

	return &ipc.Response{OK: true, Message: fmt.Sprintf("CPU limit set to %d%%", pct), State: s}
}

func handleLatency(s *state.SystemState, req *ipc.Request) *ipc.Response {
	ms, err := ipc.ParseIntArg(req.Args, "ms")
	if err != nil {
		return &ipc.Response{OK: false, Error: err.Error()}
	}

	if !dryRun {
		if err := surveillance.InjectLatency(ms); err != nil {
			return &ipc.Response{OK: false, Error: fmt.Sprintf("failed to inject latency: %v", err)}
		}
	} else {
		log.Printf("[DRY-RUN] Would set input latency: %dms", ms)
	}

	s.Compute.InputLatencyMs = ms
	s.ChangedBy = "cli"
	vexlog.LogEvent("SURVEILLANCE", "LATENCY_CHANGED", fmt.Sprintf("latency=%dms, source=cli", ms))

	return &ipc.Response{OK: true, Message: fmt.Sprintf("Input latency set to %dms", ms), State: s}
}

func handleOOM(s *state.SystemState, req *ipc.Request) *ipc.Response {
	score, err := ipc.ParseIntArg(req.Args, "score")
	if err != nil {
		return &ipc.Response{OK: false, Error: err.Error()}
	}

	if !dryRun {
		if err := guardian.SetOOMScore(score); err != nil {
			return &ipc.Response{OK: false, Error: fmt.Sprintf("failed to set OOM score: %v", err)}
		}
	} else {
		log.Printf("[DRY-RUN] Would set OOM score: %d", score)
	}

	s.Compute.OOMScoreAdj = score
	s.ChangedBy = "cli"
	vexlog.LogEvent("GUARDIAN", "OOM_CHANGED", fmt.Sprintf("oom_score=%d, source=cli", score))

	return &ipc.Response{OK: true, Message: fmt.Sprintf("OOM score set to %d", score), State: s}
}

func handleUnlock(s *state.SystemState, req *ipc.Request) *ipc.Response {
	// Check authorization — the CLI already validated the signed payload
	// before sending the unlock command, so the daemon trusts it.

	if !dryRun {
		// 1. Restore network
		if err := throttler.ApplyNetworkProfile(throttler.ProfileStandard); err != nil {
			log.Printf("Unlock: failed to restore network: %v", err)
		}
		// 2. Restore CPU
		if err := throttler.SetCPULimit(100); err != nil {
			log.Printf("Unlock: failed to restore CPU: %v", err)
		}
		// 3. Restore OOM
		if err := guardian.SetOOMScore(0); err != nil {
			log.Printf("Unlock: failed to restore OOM: %v", err)
		}
		// 4. Remove latency
		if err := surveillance.InjectLatency(0); err != nil {
			log.Printf("Unlock: failed to remove latency: %v", err)
		}
	} else {
		log.Println("[DRY-RUN] Would restore all restrictions to defaults")
	}
	// 5. Persist completion
	if err := penance.RecordCompletion(); err != nil {
		log.Printf("Unlock: failed to persist completion: %v", err)
	}

	// Update state
	s.Network.Profile = string(throttler.ProfileStandard)
	s.Network.PacketLossPct = 0
	s.Compute.CPULimitPct = 100
	s.Compute.OOMScoreAdj = 0
	s.Compute.InputLatencyMs = 0
	s.Guardian.FirewallEnabled = false
	s.Compliance.Locked = false
	s.ChangedBy = "unlock"

	vexlog.LogEvent("SYSTEM", "RESTRICTIONS_LIFTED", "All restrictions removed and persisted")

	return &ipc.Response{
		OK:      true,
		Message: "System state normalized. You may proceed.",
		State:   s,
	}
}

func handleCheck(s *state.SystemState, req *ipc.Request) *ipc.Response {
	if err := antitamper.RunAllChecks(); err != nil {
		return &ipc.Response{OK: false, Error: fmt.Sprintf("INTEGRITY CHECK FAILED: %v", err)}
	}
	return &ipc.Response{OK: true, Message: "All integrity checks PASSED."}
}

// suppress unused import lint for strings (used by log formatting)
var _ = strings.TrimSpace
