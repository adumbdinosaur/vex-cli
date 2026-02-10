# VEX-CLI Agent Operations Guide

You are operating a split-architecture enforcement system composed of two
binaries and a set of configuration files. This document tells you everything
you need to build, run, test, and troubleshoot it.

---

## 1. Architecture Overview

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

- **vexd** is the daemon. It initialises subsystems, applies kernel-level
  enforcement (qdiscs, nftables, cgroups, OOM, input latency), listens on a
  Unix domain socket, and persists unified state to disk.
- **vex-cli** is the thin control-plane client. It translates CLI arguments
  into IPC requests, sends them to vexd, prints the response, and exits.
- Both binaries **must be run as root** (`sudo`).

### IPC Transport

| Detail          | Value                               |
|-----------------|-------------------------------------|
| Socket path     | `/run/vex-cli/vexd.sock`            |
| Protocol        | Newline-delimited JSON              |
| Timeout         | 10 seconds per request              |
| Auth            | Root-only socket (mode `0660`)      |

---

## 2. File Layout

### Binaries (after build)

| Binary      | Source                | Purpose                  |
|-------------|-----------------------|--------------------------|
| `bin/vexd`  | `cmd/vexd/main.go`   | Enforcement daemon       |
| `bin/vex-cli`| `cmd/vex-cli/main.go`| Control-plane client     |

### Configuration (read-only, deployed by NixOS or manually)

| File                                   | Purpose                                      |
|----------------------------------------|----------------------------------------------|
| `/etc/vex-cli/penance-manifest.json`   | Active penance task, overrides, constraints   |
| `/etc/vex-cli/compliance-status.json`  | Compliance state (locked/unlocked, score)     |
| `/etc/vex-cli/forbidden-apps.json`     | Process names the Guardian reaper will kill   |
| `/etc/vex-cli/blocked-domains.json`    | Additional SNI domains to firewall (optional) |
| `/etc/vex-cli/vex_management_key.pub`  | Ed25519 public key for signed commands        |

### Runtime State (read-write, managed by vexd)

| File                                    | Purpose                                     |
|-----------------------------------------|---------------------------------------------|
| `/var/lib/vex-cli/system-state.json`    | Unified persisted state (survives reboots)  |
| `/run/vex-cli/vexd.sock`               | Unix domain socket for IPC                  |
| `/var/log/vex-cli.log`                  | Append-only audit log                       |

### State JSON Schema

```json
{
  "version": "1.0",
  "last_updated": "2026-02-10T11:55:58Z",
  "changed_by": "cli | penance | unlock | daemon | default",
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
    "reaper_enabled": true
  },
  "compliance": {
    "locked": false,
    "failure_score": 0,
    "task_status": "pending | completed | unknown"
  }
}
```

---

## 3. Building

The project uses Go 1.25+ with CGO enabled and requires a nix-shell for
native dependencies (libnftnl, libmnl, libevdev, linux headers).

```bash
cd /home/toy/vex-cli

# Enter the development shell (provides Go + C toolchain + libs)
nix-shell

# Build both binaries into bin/
go build -o bin/vexd ./cmd/vexd
go build -o bin/vex-cli ./cmd/vex-cli

# Run tests
go test ./...

# Run vet
go vet ./...
```

Or as a one-liner:

```bash
nix-shell --run "go build -o bin/vexd ./cmd/vexd && go build -o bin/vex-cli ./cmd/vex-cli"
```

**Important:** After any code change, you MUST rebuild both binaries. The CLI
and daemon are separate executables and stale binaries cause confusing
mismatches.

---

## 4. Running

### Start the daemon

```bash
# PRODUCTION (applies real kernel changes — qdiscs, nftables, cgroups):
sudo ./bin/vexd

# TESTING (no kernel side-effects, state tracking + IPC only):
sudo ./bin/vexd --dry-run

# With explicit network interface (if auto-detection fails):
sudo VEX_INTERFACE=enp9s0 ./bin/vexd
```

The daemon blocks in the foreground. It logs to stderr and to
`/var/log/vex-cli.log`. Send SIGINT (Ctrl+C) or SIGTERM to stop it. On
shutdown it cleans up qdiscs and nftables rules (unless `--dry-run`).

**Readiness indicator:** Wait for the log line:
```
IPC: Listening on /run/vex-cli/vexd.sock
```
Only after this line will the CLI be able to connect.

### Use the CLI (separate terminal)

All commands require the daemon to be running.

```bash
# Human-readable status report
sudo ./bin/vex-cli status

# Machine-readable JSON state dump (for scripts / waybar)
sudo ./bin/vex-cli state

# Change network throttle profile
sudo ./bin/vex-cli throttle <profile>
#   profiles: standard, choke, dial-up, black-hole, blackout (alias)

# Set CPU limit (cgroup v2)
sudo ./bin/vex-cli cpu <percent>        # e.g. "cpu 50" for 50%

# Set keyboard input latency
sudo ./bin/vex-cli latency <ms>         # e.g. "latency 200" for 200ms

# Set OOM score adjustment
sudo ./bin/vex-cli oom <score>          # -1000 to 1000

# Domain blocklist management
sudo ./bin/vex-cli block list            # list blocked domains
sudo ./bin/vex-cli block add <domain>    # add domain to SNI blocklist
sudo ./bin/vex-cli block rm <domain>     # remove domain from blocklist
sudo ./bin/vex-cli block <domain>        # shorthand for 'block add'

# Writing-lines task (disciplinary)
sudo ./bin/vex-cli lines set 50 "I will not play games during work hours"
sudo ./bin/vex-cli lines status          # show progress
sudo ./bin/vex-cli lines submit          # interactive: type lines one at a time
sudo ./bin/vex-cli lines clear           # cancel the task

# Lift all restrictions (requires signed authorization JSON)
sudo ./bin/vex-cli unlock '<signed_json_payload>'

# Run anti-tamper integrity checks
sudo ./bin/vex-cli check

# Interactive penance submission (reads from stdin)
sudo ./bin/vex-cli penance
```

---

## 5. IPC Protocol

The CLI communicates with the daemon over JSON-encoded messages on the Unix
socket. Every exchange is one request followed by one response.

### Request format

```json
{
  "command": "throttle",
  "args": {
    "profile": "choke"
  }
}
```

### Response format

```json
{
  "ok": true,
  "message": "Network profile set to: choke",
  "state": { ... }
}
```

### Command reference

| Command      | Args                             | Side-effects                         |
|--------------|----------------------------------|--------------------------------------|
| `status`     | none                             | Refreshes compliance from disk       |
| `state`      | none                             | Raw state dump, no refresh           |
| `throttle`   | `{"profile": "<name>"}`          | Applies qdisc to network interface   |
| `cpu`        | `{"percent": "<int>"}`           | Writes cgroup v2 cpu.max             |
| `latency`    | `{"ms": "<int>"}`                | Injects keyboard input delay         |
| `oom`        | `{"score": "<int>"}`             | Writes /proc/self/oom_score_adj      |
| `block-add`  | `{"domain": "<fqdn>"}`          | Adds SNI block rule, rebuilds fw     |
| `block-rm`   | `{"domain": "<fqdn>"}`          | Removes SNI block rule, rebuilds fw  |
| `block-list` | none                             | Returns blocked domains in state     |
| `lines-set`  | `{"phrase":"...","count":"N"}`  | Sets a writing-lines task            |
| `lines-clear`| none                             | Cancels the active writing task      |
| `lines-status`| none                            | Returns writing task progress        |
| `lines-submit`| `{"line": "..."}`               | Submits one line, validates match    |
| `unlock`     | none                             | Restores all to defaults, persists   |
| `check`      | none                             | Runs anti-tamper checks (NixOS integrity check currently disabled) |

Every handler that mutates state also auto-persists to
`/var/lib/vex-cli/system-state.json` after the handler returns.

---

## 6. Dry-Run Mode

`--dry-run` is critical for testing. It:

- **Skips** all subsystem initialization (throttler, guardian, surveillance,
  penance, anti-tamper)
- **Skips** all kernel operations in IPC handlers (qdiscs, nftables, cgroups,
  OOM, latency)
- **Preserves** full IPC server functionality — CLI commands work normally
- **Preserves** state tracking and persistence to disk
- **Logs** `[DRY-RUN] Would apply network profile: choke` etc. for each
  skipped operation
- **Skips** cleanup on shutdown (nothing to clean up)

Dry-run is the correct mode when:
- You want to test the CLI ↔ daemon IPC flow
- You're on a machine where kernel operations would be destructive
- You're developing new commands or debugging state persistence

---

## 7. Network Profiles

| Profile       | Behavior                                               |
|---------------|--------------------------------------------------------|
| `standard`    | Unrestricted (clears all qdiscs)                       |
| `choke`       | ~2 Mbps with TBF shaping                              |
| `dial-up`     | ~56 Kbps with Netem delay/jitter                       |
| `black-hole`  | ~1 Kbps, effectively no connectivity                   |
| `blackout`    | Alias for `black-hole`                                 |

Profile aliases also include `uncapped` → `standard`.

---

## 8. Subsystems (owned by vexd)

| Subsystem      | Package                         | What it does                           |
|----------------|---------------------------------|----------------------------------------|
| Throttler      | `internal/throttler`            | tc/qdisc shaping, cgroup CPU limits    |
| Guardian       | `internal/guardian`             | nftables SNI blocking, process reaper  |
| Surveillance   | `internal/surveillance`         | Keyboard monitoring, latency injection |
| Penance        | `internal/penance`              | Manifest loading, compliance checks    |
| Anti-tamper    | `internal/antitamper`           | Binary/service integrity verification (NixOS config check temporarily disabled) |
| Logging        | `internal/logging`              | Append-only audit log                  |
| Security       | `internal/security`             | Ed25519 signed command verification    |
| State          | `internal/state`                | Unified state load/save                |
| IPC            | `internal/ipc`                  | Unix socket server/client, protocol    |

---

## 9. Common Troubleshooting

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

### Stale state from a previous run

If the daemon starts with wrong state (e.g. locked when it shouldn't be):

```bash
# Delete persisted state (daemon will start fresh with defaults)
sudo rm /var/lib/vex-cli/system-state.json

# The compliance-status.json at /etc/vex-cli/ is the authority for
# locked/unlocked. Edit it if needed:
sudo cat /etc/vex-cli/compliance-status.json
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

---

## 10. NixOS Deployment

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

This creates a `vexd.service` systemd unit that starts on boot, creates
`/run/vex-cli` and `/var/lib/vex-cli` directories, and makes both `vexd` and
`vex-cli` available in `$PATH`.

---

## 11. Waybar / Status Bar Integration

The `vex-status.sh` script queries the daemon via `vex-cli state` and outputs
i3bar-compatible JSON. It polls every 2 seconds.

```bash
# In waybar config, point a custom module at:
/path/to/vex-status.sh

# Or override the vex-cli binary path:
VEX_CLI=/path/to/vex-cli /path/to/vex-status.sh
```

The script shows: lock state, network profile icon, failure score, CPU limit,
task status, and a firewall indicator when active.

---

## 12. Quick Reference Card

```
# Build
nix-shell --run "go build -o bin/vexd ./cmd/vexd && go build -o bin/vex-cli ./cmd/vex-cli"

# Test
nix-shell --run "go test ./..."

# Start daemon (safe)
sudo ./bin/vexd --dry-run

# Start daemon (real enforcement)
sudo VEX_INTERFACE=enp9s0 ./bin/vexd

# Query state
sudo ./bin/vex-cli status       # human-readable
sudo ./bin/vex-cli state        # JSON

# Modify state
sudo ./bin/vex-cli throttle standard
sudo ./bin/vex-cli cpu 100
sudo ./bin/vex-cli latency 0
sudo ./bin/vex-cli oom 0

# Stop daemon
Ctrl+C or: sudo kill -TERM $(pgrep vexd)

# Reset everything
sudo rm /var/lib/vex-cli/system-state.json
sudo nft delete table ip vex-guardian 2>/dev/null
sudo tc qdisc del dev enp9s0 root 2>/dev/null
```
