# VEX-CLI Agent Operations Guide

> **PURPOSE**: This document is the single source of truth for building,
> deploying, operating, and modifying the vex-cli enforcement system. It is
> structured for consumption by AI coding agents and human operators alike.

---

## TABLE OF CONTENTS

1.  [Common Operations (Quick-Start)](#1-common-operations-quick-start)
2.  [Architecture Overview](#2-architecture-overview)
3.  [File Layout & Paths](#3-file-layout--paths)
4.  [Data Schemas](#4-data-schemas)
5.  [Building](#5-building)
6.  [Running](#6-running)
7.  [CLI Command Reference](#7-cli-command-reference)
8.  [IPC Protocol (Daemon ↔ CLI)](#8-ipc-protocol-daemon--cli)
9.  [Subsystem Deep-Dive](#9-subsystem-deep-dive)
10. [Configuration Files](#10-configuration-files)
11. [Default Generation Behavior](#11-default-generation-behavior)
12. [Security & Authorization](#12-security--authorization)
13. [Dry-Run Mode](#13-dry-run-mode)
14. [NixOS Deployment](#14-nixos-deployment)
15. [Waybar / Status Bar Integration](#15-waybar--status-bar-integration)
16. [Troubleshooting](#16-troubleshooting)
17. [Development Conventions](#17-development-conventions)
18. [Quick Reference Card](#18-quick-reference-card)

---

## 1. Common Operations (Quick-Start)

> **PREREQUISITE**: The vexd daemon must be running. All commands require root.
>
> ```bash
> # Start daemon (safe / no kernel changes):
> sudo ./bin/vexd --dry-run
>
> # Start daemon (real enforcement):
> sudo VEX_INTERFACE=enp9s0 ./bin/vexd
> ```
>
> Wait for `IPC: Listening on /run/vex-cli/vexd.sock` before running any
> vex-cli command.

### 1.1 Check Current State

```bash
# Human-readable status report (compliance, network, compute, guardian, writing task)
sudo vex-cli status

# Machine-readable JSON dump (for scripts, waybar, automation)
sudo vex-cli state
```

### 1.2 Apply Network Throttling

```bash
# Restrict to ~1 Mbps
sudo vex-cli throttle choke

# Restrict to ~56 Kbps (dial-up)
sudo vex-cli throttle dial-up

# Effectively kill connectivity (~1 Kbps)
sudo vex-cli throttle black-hole

# Remove all network restrictions
sudo vex-cli throttle standard
```

Available profile names (case-insensitive): `standard` / `uncapped`,
`choke` / `throttle`, `dial-up` / `dialup` / `56k`,
`black-hole` / `blackhole` / `blackout` / `drop`.

### 1.3 Limit CPU

```bash
# Cap CPU to 25%
sudo vex-cli cpu 25

# Cap CPU to 50%
sudo vex-cli cpu 50

# Remove CPU cap (full speed)
sudo vex-cli cpu 100
```

Writes to cgroup v2 `cpu.max`. Range: 0-100.

### 1.4 Inject Keyboard Input Latency

```bash
# Add 200ms delay to every keypress
sudo vex-cli latency 200

# Add 50ms delay
sudo vex-cli latency 50

# Remove latency
sudo vex-cli latency 0
```

### 1.5 Adjust OOM Score

```bash
# Make process least likely to be killed (-1000 = invincible)
sudo vex-cli oom -1000

# Make process most likely to be killed
sudo vex-cli oom 1000

# Reset to default
sudo vex-cli oom 0
```

### 1.6 Assign a Writing-Lines Task

This is a disciplinary task where the subject must type an exact phrase
repeatedly.

```bash
# Assign: type "I will not play games during work hours" 50 times
sudo vex-cli lines set 50 "I will not play games during work hours"

# Check progress
sudo vex-cli lines status

# Subject submits lines interactively (one per line, Ctrl+D to stop)
sudo vex-cli lines submit

# Cancel the task
sudo vex-cli lines clear
```

**How it works**: Each submitted line is compared case-sensitively
(whitespace-trimmed) to the assigned phrase. Mistyped lines are rejected and
not counted. Progress is persisted in system-state.json and survives reboots.
When all required lines are submitted, the task is automatically cleared.

### 1.7 Block / Unblock Domains

```bash
# Block a domain (resolves to IPs, creates nftables drop rules)
sudo vex-cli block add reddit.com

# Block another (shorthand)
sudo vex-cli block twitch.tv

# List all currently blocked domains
sudo vex-cli block list

# Remove a domain from the blocklist
sudo vex-cli block rm reddit.com
```

### 1.8 Run Interactive Penance Task

```bash
sudo vex-cli penance
```

Loads the penance manifest from `/etc/vex-cli/penance-manifest.json` (auto-
generates a default if missing), displays task instructions (topic, word count,
required phrases, constraints), then reads multi-line text from stdin until
EOF (Ctrl+D). Validates word count, required phrases, typing speed, and
backspace violations. On success, the system unlocks automatically.

### 1.9 Run Integrity Checks

```bash
sudo vex-cli check
```

Checks: binary hash, NixOS config, systemd service status, debugger detection.

### 1.10 Lift All Restrictions (Requires Authorization)

```bash
# Requires a signed JSON payload from the management key holder
sudo vex-cli unlock '{"command":"unlock","args":"","timestamp":1707580800,"signature":"<hex>"}'

# Reset failure score to zero (also requires signed payload)
sudo vex-cli reset-score '{"command":"reset-score","args":"","timestamp":1707580800,"signature":"<hex>"}'
```

These commands verify an Ed25519 signature against the public key at
`/etc/vex-cli/vex_management_key.pub`. Without a valid signature, the
command is rejected.

### 1.11 Apply Multiple Restrictions at Once

There is no single "apply punishment" command — compose individual commands:

```bash
# Example: moderate punishment
sudo vex-cli throttle choke
sudo vex-cli cpu 50
sudo vex-cli latency 100
sudo vex-cli block add reddit.com
sudo vex-cli block add youtube.com
sudo vex-cli lines set 25 "I will stay focused on my work"

# Example: severe punishment
sudo vex-cli throttle black-hole
sudo vex-cli cpu 15
sudo vex-cli latency 300
sudo vex-cli lines set 100 "I will not waste company time"

# Example: lift everything (without signed unlock)
sudo vex-cli throttle standard
sudo vex-cli cpu 100
sudo vex-cli latency 0
sudo vex-cli oom 0
```

Each command takes effect immediately and persists across reboots.

---

## 2. Architecture Overview

```
┌─────────────┐    Unix socket     ┌──────────────────────────┐
│  vex-cli    │ ──── JSON IPC ───▶ │  vexd (daemon)           │
│  (thin CLI) │ ◀─── Response ──── │  owns all subsystems     │
└─────────────┘                    │  persists state to disk  │
  Runs once per                    │  applies kernel changes  │
  invocation, exits                └──────────────────────────┘
                                     Runs as a long-lived
                                     systemd service (or manual)
```

### Component Summary

| Component   | Binary       | Source               | Lifecycle                  | Runs as |
|-------------|--------------|----------------------|----------------------------|---------|
| **vexd**    | `bin/vexd`   | `cmd/vexd/main.go`  | Long-lived daemon          | root    |
| **vex-cli** | `bin/vex-cli`| `cmd/vex-cli/main.go`| One-shot per invocation   | root    |

### What Each Component Does

**vexd (daemon)**:
- Initialises all subsystems on startup (throttler, guardian, surveillance,
  penance, anti-tamper)
- Applies kernel-level enforcement: tc/qdiscs, nftables, cgroups, OOM scores,
  input latency
- Listens on a Unix domain socket for IPC requests from vex-cli
- Persists unified system state to `/var/lib/vex-cli/system-state.json` after
  every mutation
- Cleans up kernel state (qdiscs, nftables) on graceful shutdown (SIGINT/SIGTERM)
- Supports `--dry-run` mode that skips all kernel operations

**vex-cli (client)**:
- Translates CLI arguments into JSON IPC requests
- Sends request to vexd over the Unix socket, prints the response, and exits
- Two commands are handled locally without the daemon: `penance` (interactive
  stdin session) and initial compliance state logging
- Both binaries **require root** (`sudo`); vex-cli checks `os.Geteuid() == 0`

### IPC Transport

| Detail          | Value                               |
|-----------------|-------------------------------------|
| Socket path     | `/run/vex-cli/vexd.sock`            |
| Protocol        | Newline-delimited JSON over Unix stream socket |
| Timeout         | 10 seconds per request              |
| Auth            | Socket mode `0660` (root-only)      |
| Direction       | Client sends one `Request`, daemon sends one `Response` |

### Startup Order (Daemon — `cmd/vexd/main.go`)

```
1. Parse --dry-run flag
2. Init logging → /var/log/vex-cli.log (chattr +a attempted)
3. Init security → load /etc/vex-cli/vex_management_key.pub
4. Load persisted state from /var/lib/vex-cli/system-state.json (or defaults)
5. Sync compliance snapshot from /etc/vex-cli/compliance-status.json
6. If NOT dry-run:
   a. Init throttler (detect network interface or use VEX_INTERFACE env)
   b. Apply persisted network state (profile + packet loss)
   c. Apply persisted compute state (CPU limit, OOM score)
   d. Init guardian (eBPF or /proc reaper, nftables if penalty active)
   e. Restore persisted blocked domains
   f. Init surveillance (keyboard device scanning, latency injection)
   g. Init penance (load manifest, enforce overrides if system locked)
   h. Init anti-tamper (integrity checks + 60s periodic monitor)
7. Persist resolved state to disk
8. Start IPC server on /run/vex-cli/vexd.sock
9. Register all command handlers
10. Log "All subsystems initialized. Daemon ready."
11. Block on SIGINT/SIGTERM → cleanup → exit
```

---

## 3. File Layout & Paths

### Source Structure

```
cmd/
  vex-cli/main.go          # CLI entry point (501 lines)
  vexd/main.go             # Daemon entry point (583 lines)
internal/
  antitamper/antitamper.go  # Integrity checks, escalation
  guardian/guardian.go       # nftables, process reaper, eBPF monitor
  guardian/ebpf_monitor.go  # eBPF-based process monitoring
  ipc/client.go             # Unix socket client
  ipc/server.go             # Unix socket server + handler dispatch
  ipc/protocol.go           # Request/Response structs, command constants
  logging/logging.go        # Dual stdout+file logger, chattr +a
  penance/penance.go        # Manifest, compliance, validation
  security/security.go      # Ed25519 key loading, signature verification
  state/state.go            # Unified SystemState load/save
  surveillance/surveillance.go  # Keyboard monitoring, KPM metrics
  surveillance/wrapper.go   # evdev abstraction layer
  throttler/throttler.go    # tc/qdisc profiles, cgroup CPU limits
```

### Filesystem Paths (Runtime)

| Path                                    | Type       | Owner     | Purpose                                      |
|-----------------------------------------|------------|-----------|----------------------------------------------|
| `/etc/vex-cli/`                         | Directory  | Deploy    | All configuration files                      |
| `/etc/vex-cli/penance-manifest.json`    | Config     | Deploy/Auto | Penance task definition + system overrides |
| `/etc/vex-cli/compliance-status.json`   | State      | Penance   | Compliance state (locked/unlocked, score)    |
| `/etc/vex-cli/forbidden-apps.json`      | Config     | Deploy    | Process names the Guardian reaper kills      |
| `/etc/vex-cli/blocked-domains.json`     | Config     | Deploy    | Additional SNI domains to firewall (optional)|
| `/etc/vex-cli/vex_management_key.pub`   | Config     | Deploy    | Ed25519 public key for signed commands       |
| `/var/lib/vex-cli/system-state.json`    | State      | vexd      | Unified persisted state (survives reboots)   |
| `/var/lib/vex-cli/throttler-state.json` | State      | Penance   | Throttler-specific persisted state           |
| `/run/vex-cli/vexd.sock`               | Socket     | vexd      | Unix domain socket for IPC                   |
| `/var/log/vex-cli.log`                  | Log        | Logging   | Append-only audit log (chattr +a)            |

### Path Constants in Code

| Constant                        | Package    | Value                                  |
|---------------------------------|------------|----------------------------------------|
| `penance.ConfigDir`             | penance    | `/etc/vex-cli`                         |
| `penance.ManifestFile`          | penance    | `/etc/vex-cli/penance-manifest.json`   |
| `penance.complianceStatusFile`  | penance    | `/etc/vex-cli/compliance-status.json`  |
| `state.StateDir`                | state      | `/var/lib/vex-cli`                     |
| `state.StateFile`               | state      | `/var/lib/vex-cli/system-state.json`   |
| `state.SocketPath`              | state      | `/run/vex-cli/vexd.sock`              |
| `logging.LogFilePath`           | logging    | `/var/log/vex-cli.log`                 |
| `security.PublicKeyFile`        | security   | `/etc/vex-cli/vex_management_key.pub`  |

---

## 4. Data Schemas

### 4.1 System State (`/var/lib/vex-cli/system-state.json`)

This is the single source of truth the daemon reads on startup and persists
after every IPC mutation.

```json
{
  "version": "1.0",
  "last_updated": "2026-02-10T11:55:58Z",
  "changed_by": "cli | penance | unlock | daemon | default | escalation",
  "network": {
    "profile": "standard | choke | dial-up | black-hole",
    "packet_loss_pct": 0.0
  },
  "compute": {
    "cpu_limit_pct": 100,
    "oom_score_adj": 0,
    "input_latency_ms": 0
  },
  "guardian": {
    "firewall_enabled": false,
    "reaper_enabled": true,
    "blocked_domains": []
  },
  "compliance": {
    "locked": false,
    "failure_score": 0,
    "task_status": "pending | in_progress | completed | failed | unknown"
  },
  "writing": {
    "active": false,
    "phrase": "",
    "required": 0,
    "completed": 0
  }
}
```

### 4.2 Compliance Status (`/etc/vex-cli/compliance-status.json`)

Authoritative compliance state. The system-state.json `compliance` block is a
convenience snapshot; this file is the source of truth for lock/score.

```json
{
  "failure_score": 0,
  "active_task": "",
  "task_status": "pending | in_progress | completed | failed",
  "last_updated": "2026-02-10T11:55:58Z",
  "total_failures": 0,
  "total_completed": 0,
  "locked": true
}
```

**Behavior when missing**: `LoadComplianceStatus()` returns a default with
`failure_score=0`, `task_status="pending"`, `locked=true`.

### 4.3 Penance Manifest (`/etc/vex-cli/penance-manifest.json`)

Defines active penance tasks, system overrides, and escalation thresholds.

```json
{
  "manifest_version": "1.06-V",
  "meta": {
    "target_id": "Worker-LXC-106",
    "last_updated": "2026-02-10T02:42:00Z",
    "authorization": "VEX_MANAGEMENT_KEY_SIG_REQUIRED"
  },
  "active_penance": {
    "task_id": "PENANCE-001",
    "type": "technical_summary | line_writing | config_audit",
    "required_content": {
      "topic": "Description of what must be written",
      "min_word_count": 200,
      "validation_strings": ["phrase that must appear"]
    },
    "constraints": {
      "allow_backspace": false,
      "min_kpm": 30,
      "max_kpm": 200,
      "enforce_rhythm": true
    }
  },
  "system_state_overrides": {
    "network": {
      "profile": "standard | choke | dial-up | black-hole",
      "packet_loss_pct": 0.0,
      "dns_filtering": "none | strict"
    },
    "compute": {
      "cpu_limit_pct": 100,
      "oom_score_adj": 0,
      "input_latency_ms": 0
    }
  },
  "escalation_matrix": {
    "score_thresholds": {
      "0":   { "task_pool": ["config_audit"],        "latency": 0 },
      "50":  { "task_pool": ["line_writing"],         "latency": 10 },
      "100": { "task_pool": ["technical_summary"],    "latency": 50 },
      "250": { "task_pool": ["black_hole_isolation"], "latency": 200 }
    }
  }
}
```

**Behavior when missing**: `LoadManifest()` auto-generates and persists a
default manifest (see [Section 11](#11-default-generation-behavior)).

### 4.4 Forbidden Apps (`/etc/vex-cli/forbidden-apps.json`)

```json
{
  "forbidden_apps": ["steam", "discord", "gamescope", "lutris", "heroic"]
}
```

**Behavior when missing**: Guardian uses hardcoded defaults and attempts to
create the file.

### 4.5 Blocked Domains (`/etc/vex-cli/blocked-domains.json`)

```json
{
  "blocked_domains": ["store.steampowered.com", "reddit.com", "twitch.tv", "youtube.com"]
}
```

**Behavior when missing**: Guardian uses hardcoded default entertainment domains.

---

## 5. Building

### Prerequisites

- **Go 1.25+** with CGO enabled
- **nix-shell** for native C dependencies (libnftnl, libmnl, libevdev, linux headers)
- **Module**: `github.com/adumbdinosaur/vex-cli`
- **Vendored**: all dependencies are in `vendor/`

### Build Commands

```bash
cd /home/toy/vex-cli

# Enter the development shell (provides Go + C toolchain + libs)
nix-shell

# Build both binaries into bin/
go build -o bin/vexd ./cmd/vexd
go build -o bin/vex-cli ./cmd/vex-cli

# Run all tests
go test ./...

# Run vet
go vet ./...
```

One-liner:

```bash
nix-shell --run "go build -o bin/vexd ./cmd/vexd && go build -o bin/vex-cli ./cmd/vex-cli"
```

### CRITICAL: After any code change, rebuild BOTH binaries

The CLI and daemon are separate executables. Stale binaries cause confusing
protocol mismatches. Always rebuild both after editing any `internal/` package.

### Key Build Dependencies

| Dependency              | Go Package                      | Purpose                        |
|-------------------------|---------------------------------|--------------------------------|
| `vishvananda/netlink`   | `internal/throttler`            | tc/qdisc manipulation          |
| `google/nftables`       | `internal/guardian`             | Firewall rules                 |
| `holoplot/go-evdev`     | `internal/surveillance`         | Keyboard device scanning       |
| `cilium/ebpf`           | `internal/guardian`             | eBPF process monitoring        |
| `golang.org/x/sys`      | `internal/guardian`             | Unix syscall constants         |

---

## 6. Running

### Start the Daemon

```bash
# PRODUCTION (applies real kernel changes — qdiscs, nftables, cgroups):
sudo ./bin/vexd

# TESTING (no kernel side-effects, state tracking + IPC only):
sudo ./bin/vexd --dry-run

# With explicit network interface (if auto-detection fails):
sudo VEX_INTERFACE=enp9s0 ./bin/vexd

# Set process monitoring mode explicitly:
sudo VEX_MONITOR_MODE=proc ./bin/vexd   # Use /proc polling instead of eBPF
sudo VEX_MONITOR_MODE=ebpf ./bin/vexd   # Force eBPF only
sudo VEX_MONITOR_MODE=auto ./bin/vexd   # Try eBPF, fallback to /proc (default)
```

The daemon blocks in the foreground. It logs to stderr and to
`/var/log/vex-cli.log`. Send SIGINT (Ctrl+C) or SIGTERM to stop it. On
shutdown it cleans up qdiscs and nftables rules (unless `--dry-run`).

**Readiness indicator:** Wait for the log line:
```
IPC: Listening on /run/vex-cli/vexd.sock
```
Only after this line will the CLI be able to connect.

### Environment Variables

| Variable            | Default   | Purpose                                         |
|---------------------|-----------|------------------------------------------------|
| `VEX_INTERFACE`     | auto-detect | Network interface for tc/qdisc operations     |
| `VEX_MONITOR_MODE`  | `auto`    | Process monitor: `ebpf`, `proc`, or `auto`     |

---

## 7. CLI Command Reference

All commands require root and a running vexd daemon (except `penance` which
is partially local).

### Status & State

| Command                  | Action                                         | Output     |
|--------------------------|-------------------------------------------------|-----------|
| `vex-cli status`         | Refreshes compliance from disk, returns state   | Human text |
| `vex-cli state`          | Returns raw state without refresh               | JSON       |

### Network Throttling

| Command                       | Action                                    |
|-------------------------------|-------------------------------------------|
| `vex-cli throttle <profile>`  | Applies traffic shaping qdisc to interface |

**Profiles** (case-insensitive, aliases supported):

| Profile       | Rate         | Implementation | Aliases                         |
|---------------|-------------|----------------|---------------------------------|
| `standard`    | Unrestricted | Clears qdiscs  | `uncapped`                      |
| `choke`       | ~1 Mbps     | TBF qdisc      | `throttle`                      |
| `dial-up`     | ~56 Kbps    | Netem qdisc    | `dialup`, `56k`                 |
| `black-hole`  | ~1 Kbps     | Netem qdisc    | `blackhole`, `blackout`, `drop` |

### Compute Controls

| Command                  | Action                                        | Range        |
|--------------------------|-----------------------------------------------|-------------|
| `vex-cli cpu <percent>`  | Sets cgroup v2 cpu.max                        | 0-100       |
| `vex-cli latency <ms>`   | Injects keyboard input delay via surveillance | 0+          |
| `vex-cli oom <score>`    | Sets /proc/self/oom_score_adj                 | -1000..1000 |

**CPU limit details**: Writes to cgroup v2 `cpu.max`. Tries paths in order:
1. `/sys/fs/cgroup/cpu.max` (containers)
2. `/sys/fs/cgroup/user.slice/cpu.max` (NixOS/systemd user processes)
3. `/sys/fs/cgroup/system.slice/cpu.max`

100% writes `"max 100000"` (unlimited). 50% writes `"50000 100000"`.

### Domain Blocklist

| Command                       | Action                                    |
|-------------------------------|-------------------------------------------|
| `vex-cli block list`          | List currently blocked domains            |
| `vex-cli block add <domain>`  | Add domain to nftables blocklist          |
| `vex-cli block rm <domain>`   | Remove domain from blocklist              |
| `vex-cli block <domain>`      | Shorthand for `block add <domain>`        |

**Implementation**: Domains are DNS-resolved to IPv4 addresses. Individual
nftables drop rules are created per resolved IP in table `vex-guardian`, chain
`filter-output` (hook: output, priority: filter). A background goroutine
re-resolves domains every 30 minutes to track CDN IP rotation.

### Writing-Lines Task

| Command                                    | Action                          |
|--------------------------------------------|---------------------------------|
| `vex-cli lines set <count> <phrase>`       | Assign phrase to write N times  |
| `vex-cli lines status`                     | Show current progress           |
| `vex-cli lines submit`                     | Interactive: type lines via stdin |
| `vex-cli lines clear`                      | Cancel the active task          |

Lines must match the exact phrase (case-sensitive, whitespace-trimmed).
Progress persists across reboots via system-state.json.

### Penance (Interactive)

```bash
sudo vex-cli penance
```

- Loads manifest from `/etc/vex-cli/penance-manifest.json` (generates default
  if missing)
- Initializes surveillance (keyboard monitoring) locally
- Displays task instructions, constraints, required phrases
- Reads multi-line input from stdin until EOF (Ctrl+D)
- Validates: word count, required phrases, typing speed (KPM), backspace violations
- On success: calls `RecordCompletion()` + sends `unlock` IPC to daemon
- On failure: calls `RecordFailure()` and exits with code 1

### Authorization-Required Commands

| Command                               | Action                                 |
|----------------------------------------|----------------------------------------|
| `vex-cli unlock '<signed_json>'`       | Lifts all restrictions, restores defaults |
| `vex-cli reset-score '<signed_json>'`  | Resets failure score to zero           |

These commands require a JSON payload signed with the Ed25519 management key.
See [Section 12](#12-security--authorization).

### Integrity Checks

| Command           | Action                                              |
|-------------------|-----------------------------------------------------|
| `vex-cli check`   | Runs anti-tamper checks via daemon                 |

Checks: binary SHA-256 integrity, NixOS config verification (nix-store
--verify), systemd service status, debugger detection (TracerPid).

---

## 8. IPC Protocol (Daemon ↔ CLI)

### Transport

Unix stream socket at `/run/vex-cli/vexd.sock`. Each connection handles
exactly one request-response pair, then the connection is closed.

### Request Schema

```json
{
  "command": "string (required)",
  "args": { "key": "value" }
}
```

### Response Schema

```json
{
  "ok": true,
  "message": "Human-readable result",
  "error": "Error description (when ok=false)",
  "state": { /* full SystemState object, included for status/state commands */ }
}
```

### Command Constants (`internal/ipc/protocol.go`)

| Constant         | Wire Value      | Args                                | Side-Effects                              |
|------------------|-----------------|-------------------------------------|-------------------------------------------|
| `CmdStatus`      | `"status"`      | none                                | Refreshes compliance from disk            |
| `CmdState`       | `"state"`       | none                                | Raw state dump, no refresh                |
| `CmdThrottle`    | `"throttle"`    | `{"profile": "<name>"}`             | Applies qdisc to network interface        |
| `CmdCPU`         | `"cpu"`         | `{"percent": "<int>"}`              | Writes cgroup v2 cpu.max                  |
| `CmdLatency`     | `"latency"`     | `{"ms": "<int>"}`                   | Sets surveillance input delay             |
| `CmdOOM`         | `"oom"`         | `{"score": "<int>"}`                | Writes /proc/self/oom_score_adj           |
| `CmdBlockAdd`    | `"block-add"`   | `{"domain": "<fqdn>"}`              | Resolves domain IPs, adds nftables rules  |
| `CmdBlockRemove` | `"block-rm"`    | `{"domain": "<fqdn>"}`              | Removes nftables rules, rebuilds          |
| `CmdBlockList`   | `"block-list"`  | none                                | Returns blocked domains in state          |
| `CmdLinesSet`    | `"lines-set"`   | `{"phrase":"...","count":"<int>"}`   | Creates writing-lines task                |
| `CmdLinesClear`  | `"lines-clear"` | none                                | Cancels active writing task               |
| `CmdLinesStatus` | `"lines-status"`| none                                | Returns writing task progress             |
| `CmdLinesSubmit` | `"lines-submit"`| `{"line": "..."}`                   | Validates one line against phrase          |
| `CmdUnlock`      | `"unlock"`      | none                                | Restores ALL settings to defaults         |
| `CmdResetScore`  | `"reset-score"` | none                                | Zeros failure score + total failures      |
| `CmdCheck`       | `"check"`       | none                                | Runs all anti-tamper integrity checks     |

### State Persistence

Every IPC handler runs, mutates the in-memory `SystemState`, and the server
auto-persists to `/var/lib/vex-cli/system-state.json` after EVERY handler
invocation (even read-only ones, to update `last_updated`).

---

## 9. Subsystem Deep-Dive

### 9.1 Throttler (`internal/throttler`)

**Purpose**: Network traffic shaping via tc/qdiscs and CPU governance via cgroup v2.

| Function                              | Action                                           |
|---------------------------------------|--------------------------------------------------|
| `Init()`                              | Detects default network interface via route table |
| `ApplyNetworkProfile(profile)`        | Clears existing qdiscs, applies new one          |
| `ApplyNetworkProfileWithEntropy(p,l)` | Combined profile + packet loss in single netem   |
| `InjectEntropy(lossPct)`              | Standalone packet loss (wraps WithEntropy)        |
| `SetCPULimit(percent)`                | Writes cgroup v2 cpu.max file                    |
| `ResolveProfile(input)`               | Normalises user input to canonical Profile        |
| `SaveState(state)` / `LoadState()`    | Persists throttler-specific state                 |

**Qdisc Implementation by Profile**:
- `standard`: Clears all qdiscs (unrestricted)
- `choke`: TBF qdisc — rate 125,000 B/s (1 Mbps), limit 1MB burst
- `dial-up`: Netem qdisc — rate 7,000 B/s (56 Kbps), 1000 pkt queue
- `black-hole`: Netem qdisc — rate 125 B/s (1 Kbps), 100 pkt queue

### 9.2 Guardian (`internal/guardian`)

**Purpose**: Process reaping (killing forbidden apps) and domain-based firewall.

**Process Reaper**:
- Tries eBPF-based monitoring first (`NewEBPFMonitor()`), falls back to /proc polling
- `/proc` polling: scans every 2 seconds, reads `/proc/<pid>/comm` and `/proc/<pid>/cmdline`
- Matches against forbidden apps list (case-insensitive substring match)
- Sends SIGKILL to matching processes

**Firewall**:
- Uses nftables table `vex-guardian` (IPv4 family)
- Chain `filter-output` (hook: output, priority: filter)
- Resolves each domain (+ www. variant) to IPs
- Creates per-IP drop rules matching TCP destination address
- Background DNS refresh every 30 minutes
- `ClearFirewall()` deletes the entire `vex-guardian` table

**OOM Protection**: Sets `/proc/self/oom_score_adj` to protect the daemon.

| Function                   | Action                                    |
|----------------------------|-------------------------------------------|
| `Init(penaltyActive)`      | Start reaper + firewall if penalty active |
| `Shutdown()`               | Stop eBPF, DNS refresh, clear nftables    |
| `AddDomain(domain)`        | Add to blocklist, rebuild firewall        |
| `RemoveDomain(domain)`     | Remove from blocklist, rebuild            |
| `SetBlockedDomains(list)`  | Replace entire blocklist                  |
| `GetBlockedDomains()`      | Return current domain list (copy)         |
| `SetOOMScore(score)`       | Write /proc/self/oom_score_adj            |

### 9.3 Surveillance (`internal/surveillance`)

**Purpose**: Keyboard monitoring for typing metrics and input latency injection.

- Scans `/dev/input/event*` for keyboard devices via evdev
- Monitors key press events (EV_KEY, value=1)
- Tracks: total keystrokes, lines completed (Enter key), KPM rate
- **Zero-storage policy**: does NOT log keycodes or maintain a buffer
- Reports metrics every 30 seconds to log

**Latency Injection**: `InjectLatency(ms)` sets a `time.Sleep()` delay in the
key event processing goroutine. Setting to 0 disables injection.

| Function                 | Action                                |
|--------------------------|---------------------------------------|
| `Init()`                 | Scan for keyboards, start listeners   |
| `InjectLatency(ms)`      | Set/clear input delay                |
| `GetCurrentKPM()`        | Return current keystrokes-per-minute |
| `GetMetricSnapshot()`    | Return (keystrokes, linesCompleted)  |

### 9.4 Penance (`internal/penance`)

**Purpose**: Manifest loading, compliance tracking, submission validation,
and escalation matrix processing.

**Key Constants**:
- `ConfigDir = "/etc/vex-cli"` — base config directory
- `ManifestFile = "/etc/vex-cli/penance-manifest.json"` — manifest path

**Manifest Loading** (`LoadManifest(path)`):
- If file exists: parse JSON, return `*Manifest`
- If file not found: generate `DefaultManifest()`, persist to disk, return it
- If other error: return error

**Compliance Status** (`LoadComplianceStatus()`):
- If file exists: parse JSON, return `*ComplianceStatus`
- If file not found: return default (score=0, locked=true, status=pending)
- Status mutations: `RecordFailure(reason)` adds +10 score; `RecordCompletion()` sets locked=false

**Submission Validation** (`ValidateSubmission(text, manifest)`):
1. Word count check against `min_word_count`
2. Required phrase presence check
3. KPM range validation (if `enforce_rhythm` is true)

**Escalation Matrix** (`SelectWeightedTask(manifest)`):
- Finds highest score threshold the current failure score exceeds
- Selects task type from that threshold's pool
- Uses time-based deterministic selection

### 9.5 Anti-Tamper (`internal/antitamper`)

**Purpose**: Detect unauthorized modifications and escalate penalties.

**Checks** (via `RunAllChecks()`):
1. Binary SHA-256 self-verification (if hash configured)
2. NixOS config integrity (`nix-store --verify --check-contents`)
3. systemd service status check (`systemctl is-active vexd.service`)
4. Debugger detection (TracerPid != 0 in `/proc/self/status`)

**Note**: If `vexd.service` unit file doesn't exist (non-systemd installs),
ALL Nix integrity checks are skipped.

**Escalation Behavior** (when tamper detected):
1. Apply `black-hole` network profile immediately
2. Double the failure score (minimum: 50, maximum cap: 500)
3. Set locked=true, task_status=failed
4. Cooldown: 30 minutes between escalations to prevent score inflation

**Periodic Monitoring**: Runs `RunAllChecks()` every 60 seconds in a background goroutine.

### 9.6 Security (`internal/security`)

**Purpose**: Ed25519 signed command verification for restriction-lowering operations.

**Key Loading**: Reads `/etc/vex-cli/vex_management_key.pub`. Supports formats:
- OpenSSH: `ssh-ed25519 <base64> <comment>`
- Hex-encoded 32-byte key
- Raw 32 bytes

**Restricted Commands** (require signed authorization):
`unlock`, `unblock`, `lift-throttle`, `restore-network`, `clear-penance`,
`set-standard`, `reset-score`

**Signature Format**: `SignedCommand` JSON with fields: `command`, `args`,
`timestamp`, `signature` (hex-encoded Ed25519 signature over `"command:args:timestamp"`).

### 9.7 Logging (`internal/logging`)

- Dual-writer: stdout + `/var/log/vex-cli.log`
- Attempts `chattr +a` to make log file append-only
- `LogCommand()`: structured command audit trail
- `LogEvent()`: structured subsystem event logging
- Falls back to stdout-only if log file can't be opened

### 9.8 State (`internal/state`)

- Unified `SystemState` struct with JSON persistence
- Thread-safe via `sync.Mutex`
- `Load()`: reads from `/var/lib/vex-cli/system-state.json`, returns `Default()` if missing
- `Save()`: creates directory if needed, writes indented JSON
- `Default()`: standard profile, 100% CPU, no latency, no firewall, unlocked

### 9.9 IPC (`internal/ipc`)

- **Server**: binds to Unix socket, dispatches to registered `Handler` functions,
  auto-persists state after every handler call
- **Client**: connects with 10s timeout, sends one request, reads one response
- **Protocol**: newline-delimited JSON (one JSON object per message)
- `ParseIntArg()`: helper for handlers that need integer arguments

---

## 10. Configuration Files

### Creating Config Directory

```bash
sudo mkdir -p /etc/vex-cli
```

### Minimal penance-manifest.json (no restrictions)

```json
{
  "manifest_version": "1.0-DEFAULT",
  "meta": {
    "target_id": "unset",
    "last_updated": "2026-02-10T00:00:00Z",
    "authorization": "none"
  },
  "active_penance": {},
  "system_state_overrides": {
    "network": {
      "profile": "standard",
      "packet_loss_pct": 0,
      "dns_filtering": "none"
    },
    "compute": {
      "cpu_limit_pct": 100,
      "oom_score_adj": 0,
      "input_latency_ms": 0
    }
  },
  "escalation_matrix": {
    "score_thresholds": {
      "0": { "task_pool": ["config_audit"], "latency": 0 }
    }
  }
}
```

### Restrictive penance-manifest.json (example)

```json
{
  "manifest_version": "1.06-V",
  "meta": {
    "target_id": "Worker-LXC-106",
    "last_updated": "2026-02-10T02:42:00Z",
    "authorization": "VEX_MANAGEMENT_KEY_SIG_REQUIRED"
  },
  "active_penance": {
    "task_id": "PENANCE-001",
    "type": "technical_summary",
    "required_content": {
      "topic": "Explain how Linux namespaces provide process isolation",
      "min_word_count": 200,
      "validation_strings": ["namespace", "isolation", "cgroup"]
    },
    "constraints": {
      "allow_backspace": false,
      "min_kpm": 30,
      "max_kpm": 200,
      "enforce_rhythm": true
    }
  },
  "system_state_overrides": {
    "network": {
      "profile": "choke",
      "packet_loss_pct": 5.0,
      "dns_filtering": "strict"
    },
    "compute": {
      "cpu_limit_pct": 50,
      "oom_score_adj": -1000,
      "input_latency_ms": 100
    }
  },
  "escalation_matrix": {
    "score_thresholds": {
      "0":   { "task_pool": ["config_audit"],        "latency": 0 },
      "50":  { "task_pool": ["line_writing"],         "latency": 10 },
      "100": { "task_pool": ["technical_summary"],    "latency": 50 },
      "250": { "task_pool": ["black_hole_isolation"], "latency": 200 }
    }
  }
}
```

---

## 11. Default Generation Behavior

When configuration files are missing, the system either generates defaults or
uses hardcoded fallbacks. This table describes each file's behavior:

| File                            | When Missing                                                    |
|---------------------------------|-----------------------------------------------------------------|
| `penance-manifest.json`        | **Auto-generated** at `/etc/vex-cli/penance-manifest.json`: standard profile, no filtering, 100% CPU, 0 latency. Written to disk for future runs. |
| `compliance-status.json`       | **In-memory default**: score=0, locked=true, status=pending. NOT written to disk until first mutation. |
| `system-state.json`            | **In-memory default**: standard profile, 100% CPU, no latency, unlocked. Written on first persist. |
| `forbidden-apps.json`          | **Auto-generated** with defaults: steam, discord, gamescope, lutris, heroic. |
| `blocked-domains.json`         | **Hardcoded fallback**: store.steampowered.com, reddit.com, twitch.tv, youtube.com. NOT written. |
| `vex_management_key.pub`       | **Warning logged**. All signed commands will be REJECTED. System continues. |

The `DefaultManifest()` function returns:

```go
Manifest{
    Version: "1.0-DEFAULT",
    Meta:    ManifestMeta{TargetID: "unset", Authorization: "none"},
    Overrides: SystemStateOverrides{
        Network: NetworkState{Profile: "standard", PacketLoss: 0, DNSFiltering: "none"},
        Compute: ComputeState{CPULimit: 100, OOMScoreAdj: 0, InputLatency: 0},
    },
    Escalation: EscalationMatrix{
        Thresholds: map[string]EscalationLevel{
            "0": {TaskPool: []string{"config_audit"}, Latency: 0},
        },
    },
}
```

---

## 12. Security & Authorization

### Signed Command Flow

```
1. External management system creates JSON: {"command":"unlock","args":"","timestamp":1707580800,"signature":"<hex>"}
2. Signature covers: "unlock::1707580800" (format: "command:args:timestamp")
3. Signed with Ed25519 private key (counterpart of vex_management_key.pub)
4. User passes JSON as CLI argument: sudo vex-cli unlock '<json>'
5. vex-cli verifies signature locally using public key
6. If valid: sends unlock IPC command to daemon (no signature forwarded)
7. Daemon trusts the CLI's pre-verification and executes
```

### Which Commands Are Restricted

The CLI gates these commands BEFORE sending to the daemon:
- `unlock`, `reset-score`, `unblock`, `lift-throttle`, `restore-network`,
  `clear-penance`, `set-standard`

Commands NOT restricted (can be run freely):
- `status`, `state`, `throttle`, `cpu`, `latency`, `oom`, `block`,
  `lines`, `penance`, `check`

### Key File Format

The public key at `/etc/vex-cli/vex_management_key.pub` can be in:
1. **OpenSSH format**: `ssh-ed25519 AAAAC3Nza... comment`
2. **Hex-encoded**: 64 hex characters representing the 32-byte key
3. **Raw binary**: exactly 32 bytes

---

## 13. Dry-Run Mode

Start with `sudo ./bin/vexd --dry-run`.

| Feature                         | Normal Mode | Dry-Run Mode |
|---------------------------------|------------|--------------|
| Subsystem initialization        | Yes        | **Skipped**  |
| tc/qdisc operations             | Yes        | **Skipped** (logged as `[DRY-RUN] Would apply...`) |
| nftables rules                  | Yes        | **Skipped**  |
| Cgroup cpu.max writes           | Yes        | **Skipped**  |
| OOM score adjustment            | Yes        | **Skipped**  |
| Input latency injection         | Yes        | **Skipped**  |
| IPC server                      | Yes        | **Yes** (fully functional) |
| State persistence to disk       | Yes        | **Yes**      |
| Audit logging                   | Yes        | **Yes**      |
| Cleanup on shutdown             | Yes        | **Skipped** (nothing to clean up) |

**Use dry-run when**:
- Testing IPC flow and CLI commands
- Developing new features
- Running on a machine where kernel operations would be destructive
- Debugging state persistence

---

## 14. NixOS Deployment

The flake provides a NixOS module. In your system flake:

```nix
{
  inputs.vex-cli.url = "path:/home/toy/vex-cli";

  outputs = { self, nixpkgs, vex-cli, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        vex-cli.nixosModules.default
        {
          services.vex-cli = {
            enable = true;
            monitorMode = "auto";
            # Optional: deploy config files declaratively
            # manifestFile = ./penance-manifest.json;
            # forbiddenAppsFile = ./forbidden-apps.json;
            # managementKeyFile = ./vex_management_key.pub;
          };
        }
      ];
    };
  };
}
```

**What the module creates**:
- `vexd.service` systemd unit (starts on boot, `WorkingDirectory=/etc/vex-cli`)
- `/run/vex-cli` and `/var/lib/vex-cli` directories (via systemd RuntimeDirectory/StateDirectory)
- Both `vexd` and `vex-cli` in system `$PATH`
- Config files deployed to `/etc/vex-cli/` (if paths specified)

---

## 15. Waybar / Status Bar Integration

The `vex-status.sh` script queries the daemon via `vex-cli state` and outputs
i3bar-compatible JSON. It polls every 2 seconds.

```bash
# In waybar config, point a custom module at:
/path/to/vex-status.sh

# Or override the vex-cli binary path:
VEX_CLI=/path/to/vex-cli /path/to/vex-status.sh
```

Shows: lock state, network profile icon, failure score, CPU limit, task
status, and a firewall indicator when active.

---

## 16. Troubleshooting

### "Failed to communicate with vexd" / socket not found

The daemon is not running, or hasn't reached the IPC listener yet.

```bash
# Check if daemon is running
ps aux | grep vexd

# Check if socket exists
ls -la /run/vex-cli/vexd.sock

# Start the daemon
sudo ./bin/vexd --dry-run
```

### "failed to find interface eth0: Link not found"

The throttler couldn't detect your network interface. Set it explicitly:

```bash
sudo VEX_INTERFACE=enp9s0 ./bin/vexd
```

Find your interface name with `ip link show`.

### "Failed to load penance manifest: no such file or directory"

The manifest wasn't at the expected path. After the fix in the current
codebase, `LoadManifest()` auto-generates a default at
`/etc/vex-cli/penance-manifest.json` if missing. Ensure `/etc/vex-cli/`
exists and is writable by root:

```bash
sudo mkdir -p /etc/vex-cli
```

### Stale state from a previous run

If the daemon starts with wrong state (e.g. locked when it shouldn't be):

```bash
# Delete persisted state (daemon will start fresh with defaults)
sudo rm /var/lib/vex-cli/system-state.json

# The compliance-status.json at /etc/vex-cli/ is the authority for
# locked/unlocked. Edit or remove it:
sudo cat /etc/vex-cli/compliance-status.json
sudo rm /etc/vex-cli/compliance-status.json  # Will default to locked=true
```

### Daemon applied nftables/qdiscs and I need to clear them manually

If the daemon crashed without cleanup:

```bash
# Clear nftables
sudo nft delete table ip vex-guardian 2>/dev/null

# Clear qdiscs on a specific interface
sudo tc qdisc del dev enp9s0 root 2>/dev/null
```

### Traffic blocked after stopping daemon

If you ran the daemon **without** `--dry-run` and killed it with SIGKILL
(instead of SIGINT/SIGTERM), it couldn't clean up. Use the manual cleanup
commands above.

### Anti-tamper keeps escalating / score keeps growing

Escalation has a 30-minute cooldown and a score cap of 500. If periodic
checks keep failing, the score won't compound during the cooldown window.
Check what's triggering it:

```bash
# Look for Anti-Tamper log entries
sudo grep "Anti-Tamper" /var/log/vex-cli.log
```

Common triggers: `vexd.service` exists but is reported as inactive (service
was stopped but unit file remains), nix store corruption.

---

## 17. Development Conventions

### Testing

All subsystems use interface-based dependency injection for testability:

| Package      | Interfaces                                      |
|--------------|-------------------------------------------------|
| penance      | `FileSystem` (ReadFile, WriteFile)              |
| throttler    | `NetlinkOps`, `FileOps`                         |
| guardian     | `FileSystem`, `SystemOps`, `FirewallOps`        |
| state        | `FileOps` (ReadFile, WriteFile, MkdirAll, Stat) |
| security     | `FileSystem` (ReadFile)                         |
| antitamper   | `CommandRunner` (Run)                           |
| surveillance | `EvdevOps` (ListInputDevices, Open)             |

Override the package-level `fsOps`, `nlOps`, `sysOps`, `fwOps`, `cmdRunner`,
or `evOps` variable in tests with mock implementations.

### Adding a New IPC Command

1. Add constant in `internal/ipc/protocol.go`:
   ```go
   CmdMyCommand = "my-command"
   ```
2. Add handler in `cmd/vexd/main.go`:
   ```go
   func handleMyCommand(s *state.SystemState, req *ipc.Request) *ipc.Response { ... }
   ```
3. Register in `registerHandlers()`:
   ```go
   srv.Handle(ipc.CmdMyCommand, handleMyCommand)
   ```
4. Add CLI command in `cmd/vex-cli/main.go`:
   - Add case in `switch command { ... }`
   - Add function `cmdMyCommand()` that calls `sendOrDie()`
   - Update `printUsage()`
5. Rebuild both binaries

### Adding a New Network Profile

1. Add constant in `internal/throttler/throttler.go`:
   ```go
   ProfileMyProfile Profile = "my-profile"
   ```
2. Add case in `ApplyNetworkProfile()` switch
3. Add case in `ApplyNetworkProfileWithEntropy()` switch
4. Add aliases in `profileAliases` map
5. Update `ResolveProfile()` error message with new profile name

---

## 18. Quick Reference Card

```bash
# ── Build ──────────────────────────────
nix-shell --run "go build -o bin/vexd ./cmd/vexd && go build -o bin/vex-cli ./cmd/vex-cli"
nix-shell --run "go test ./..."

# ── Daemon ─────────────────────────────
sudo ./bin/vexd --dry-run                     # Safe testing mode
sudo VEX_INTERFACE=enp9s0 ./bin/vexd          # Real enforcement
sudo kill -TERM $(pgrep vexd)                 # Graceful stop

# ── Query ──────────────────────────────
sudo ./bin/vex-cli status                     # Human-readable
sudo ./bin/vex-cli state                      # JSON

# ── Control ────────────────────────────
sudo ./bin/vex-cli throttle standard          # Remove network restrictions
sudo ./bin/vex-cli cpu 100                    # Remove CPU limit
sudo ./bin/vex-cli latency 0                  # Remove input latency
sudo ./bin/vex-cli oom 0                      # Reset OOM score
sudo ./bin/vex-cli block add example.com      # Block a domain
sudo ./bin/vex-cli block rm example.com       # Unblock a domain

# ── Disciplinary ───────────────────────
sudo ./bin/vex-cli penance                    # Interactive submission
sudo ./bin/vex-cli lines set 50 "I will not play games"
sudo ./bin/vex-cli lines submit               # Type lines interactively
sudo ./bin/vex-cli check                      # Run integrity checks

# ── Authorization-Required ─────────────
sudo ./bin/vex-cli unlock '<signed_json>'
sudo ./bin/vex-cli reset-score '<signed_json>'

# ── Manual Cleanup ─────────────────────
sudo rm /var/lib/vex-cli/system-state.json    # Reset persisted state
sudo nft delete table ip vex-guardian 2>/dev/null
sudo tc qdisc del dev enp9s0 root 2>/dev/null
```
