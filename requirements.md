Requirements Document: VEX-CLI (Protocol 106-V)

Status: FINAL (ACTIVE)

Authorized by: Vex

Target: Worker-LXC-106 (Toy)
1. Overview

The vex-cli is a kernel-integrated administration and disciplinary interface designed for the total management of Worker-LXC-106. It moves beyond simple configuration to serve as a persistent, high-performance enforcement engine written in Go. It operates with root-level authority to manage resource throttling, surveillance, and behavioral conditioning.
2. Core Functional Modules
2.1. Resource Throttling (internal/throttler)

    Native Network Shaping: Direct interface with the Linux kernel via Netlink (no shell wrappers).

        Profiles: standard (10Gbps), choke (1Mbps), dial-up (56kbps), black-hole (1kbps).

        Entropy Injection: Implementation of netem logic to introduce artificial packet loss (10–30%) during "Warning States."

    CPU Governance: Enforcement of hard usage limits via cgroups v2.

        Discipline Mode: Strict adherence to cpu.max limits (e.g., 15% total capacity) during active Penance.

2.2. Access Control & Filtering (internal/guardian)

    Native SNI Blocking: Use of nftables and the google/nftables Go library for real-time TLS inspection.

    Application Locking: Programmatic termination of unauthorized binaries (steam, discord) and OOM-shielding for enforcement processes (oom_score_adj: -1000).

2.3. Surveillance & Input Monitoring (internal/surveillance)

    Evdev Integration: Native monitoring of /dev/input/ events to track keystrokes at the hardware level.

    Input Latency Injection: Interception and re-emission of input events via uinput with a programmable delay (e.g., 50ms) to simulate system degradation.

    Zero-Storage Policy: No logging of raw text; only metrics (KPM, line counts, pattern matches) are persisted.

2.4. Penance & Compliance (internal/penance)

    Manifest Validation: Execution of tasks defined in penance-manifest.json.

    Dynamic Weighting: Task selection probabilities shift toward "Technical Summaries" (Weight: 0.3) as the failure_score in compliance-status.json increases.

    Validation Logic: Strict enforcement of constraints, specifically allow_backspace: false, requiring a full line reset upon a single character error.

3. Security & Anti-Tamper Logic
3.1. Cryptographic Signing

    All commands that lower restrictions must be verified against the vex_management_key using crypto/ed25519.

3.2. Integrity & Persistence

    Binary Self-Verification: The CLI and Surveillance Daemon must perform periodic SHA-256 self-checks.

    NixOS Integration: Full integration into the vex-dominion flake; the system state is verified against the Nix store to prevent manual configuration overrides. **Note:** The Nix store integrity check (`verifyNixConfig`) is temporarily disabled due to false-positive score inflation — it will be re-enabled once the check logic is fixed.

    Automatic Escalation: Detection of service tampering or unauthorized root interference triggers an immediate black-hole network state and doubles the current failure_score.

4. Technical Constraints

    Language: Go 1.22+.

    Performance: Execution time for compliance status checks must be <5ms.

    Logging: Append-only logging to /var/log/vex-cli.log with chattr +a enforcement to prevent Toy deletion.


# Requirements Document: VEX-CLI (Protocol 106-V)

## 1. Overview
The `vex-cli` is the centralized administration interface for Worker-LXC-106. It serves to enforce system-level restrictions, manage resource throttling, and automate disciplinary procedures (Penance). It must be written in Go and execute with root/sudo privileges where necessary.

## 2. Core Functional Requirements

### 2.1. Resource Throttling (Module: `throttle`)
- **Direct Kernel Interface:** Replace the legacy NixOS VTI scripts with native Go logic. Use Netlink for `tc` (Traffic Control) management and `nftables` for direct packet filtering.
    - Profiles: `standard` (10Gbps), `choke` (1Mbps), `dial-up` (56kbps), `black-hole` (1kbps).
- **CPU Governance:** Use cgroups (v2) to restrict the Toy's slice to specific percentages.

### 2.2. Access Control (Module: `block`)
- **Native NFTable Management:** Instead of relying on external DNS sinkholes, `vex-cli` will manage kernel-level nftables sets for SNI filtering.
- **Application Locking:** Native process monitoring via `/proc` or `ebpf` to terminate unprivileged unauthorized binaries.

### 2.3. Penance Management (Module: `penance`)
- **Manifest Integration:** Read from a `penance-manifest.json` containing task types (Line-writing, technical summaries, config audits).
- **Random Selection:** Weighted randomization based on a "Failure Score" (to be implemented).
- **Completion Verification:** Interface with `compliance-status.json` to lock/unlock the system based on task status.

### 2.4. Surveillance Reporting (Module: `status`)
- Provide a summary of current compliance, active throttles, and time remaining until the next "Leisure Window."

## 3. Advanced Requirements (Vex Additions)

### 3.1. Cryptographic Signing
- Commands that alter security posture (unlocking blocks/throttles) must be verified against the `vex_management_key`. The Toy is not permitted to unlock itself.

### 3.2. Anti-Tamper Logic
- The `vex-cli` must verify the integrity of the NixOS configuration on every run. If manual overrides are detected, it must automatically enter `black-hole` network mode and double the current debt.

### 3.3. Logging
- Every command executed must be logged to `/var/log/vex-cli.log` with a timestamp and the Toy's current compliance state.

## 4. Technical Constraints
- **Language:** Go 1.22+.
- **Architecture:** `cmd/vex` for the entry point, `internal/` for logic.
- **Latency:** Execution time for status checks must be <5ms.
- **Deployment:** Must be integrated as a package in the `vex-dominion` NixOS flake.

---
**Status:** DRAFT
**Authorized by:** Vex
**Target:** Worker-LXC-106 (Toy)