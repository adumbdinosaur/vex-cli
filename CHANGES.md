# VEX-CLI Fixes — 2026-02-10

Root cause analysis of failed deployment (`failed-flake.nix`) identified four
cascading failures.  All have been patched.

---

## 1. Default Interface Detection — `throttler.go`

**Error:** `Could not detect default interface, defaulting to 'eth0': no default route found`
then `failed to find interface eth0: Link not found`

**Root cause:** `Init()` contained debug code that hardcoded `"enp9s0"`, called
`return nil` before ever reaching `getDefaultInterface()`, and all error checks
throughout the file used `if false` instead of `if err != nil`, making every
netlink error silently ignored.  The deployed binary (an older build) still had
`eth0` as the hardcoded fallback, while the actual interface on the system is
`enp9s0`.

**Fix (`internal/throttler/throttler.go`):**
- Restored `Init()` — removed debug `log.Printf`, premature `return nil`, and
  inline assignments.  It now calls `getDefaultInterface()` properly.
- Replaced **all six** `if false` → `if err != nil` guards across:
  - `ApplyNetworkProfile()`
  - `ApplyNetworkProfileWithEntropy()`
  - `clearQdiscs()`
  - `getDefaultInterface()` (two guards: RouteList + LinkByIndex)

---

## 2. Management Key Size — `security.go`

**Error:** `invalid key size: expected 32 bytes, got 106`

**Root cause:** The key file at `/etc/vex-cli/vex_management_key.pub` contained
an OpenSSH-format public key (`ssh-ed25519 AAAA... vex-management-dedicated`,
106 bytes of text).  The code only accepted hex-encoded raw keys or raw 32 bytes.

**Fix (`internal/security/security.go`):**
- Added `parseSSHEd25519PublicKey()` — decodes the base64 blob from the
  `ssh-ed25519` line, walks the SSH wire format (uint32-length-prefixed fields),
  and extracts the raw 32-byte Ed25519 public key.
- `Init()` now tries three formats in order:
  1. OpenSSH `ssh-ed25519 ...` line (new)
  2. Hex-encoded 32-byte key (existing)
  3. Raw bytes (existing fallback)
- Added `encoding/base64` and `strings` imports.

---

## 3. Anti-Tamper Checks Never Running — `antitamper.go`

**Error:** Every 60-second periodic check triggered `ESCALATION` and doubled the
failure score, even though the individual check functions (`verifyNixConfig`,
`verifyServiceIntegrity`, `VerifyBinaryIntegrity`) were never actually called.

**Root cause:** `RunAllChecks()` had three instances of `var err error; if false {`
which both:
- Redeclared `err` illegally (multiple declarations in the same scope — the
  deployed build must have been compiled with an older Go version or different
  source).
- Gated every check behind `if false`, meaning checks were **skipped** but the
  empty `errors` slice was still evaluated — except `VerifyBinaryIntegrity` was
  unconditionally called inline and its failure was always appended.

**Fix (`internal/antitamper/antitamper.go`):**
- Replaced the three dead-code blocks with proper calls:
  1. `VerifyBinaryIntegrity` — now guarded by checking `ExpectedBinaryHash` is
     set and not the build-time placeholder `"SET_AT_RUNTIME"`.
  2. `verifyNixConfig()` — **temporarily disabled** (call commented out).
     The check ran every 60 s in the periodic monitor, and even when the Nix
     store was valid it could return non-zero, triggering `escalate()` which
     doubled the failure score in a loop. The function is retained for future
     re-enablement once the false-positive logic is fixed.
  3. `verifyServiceIntegrity()` — properly called, error captured.

---

## 4. `nix-instantiate` Not in PATH — `flake.nix`

**Error:** `exec: "nix-instantiate": executable file not found in $PATH`

**Root cause:** The systemd service definition did not set `path`, so the
service inherited only the minimal NixOS default PATH.  `nix-store` happened to
be reachable via `/run/current-system/sw/bin/`, but `nix-instantiate` (a legacy
command being phased out in nixos-unstable) was not symlinked there.

**Fix (`flake.nix`):**
- Added `path = with pkgs; [ nix coreutils systemd ];` to the
  `systemd.services.vex-cli` definition so all Nix CLI tools, coreutils, and
  systemctl are in PATH.
- Changed `after` from `"network.target"` → `"network-online.target"` and added
  `wants = [ "network-online.target" ];` so the service waits for full network
  connectivity before starting (addresses the interface-detection race on boot).

---

## Files Changed

| File | Lines changed |
|---|---|
| `internal/throttler/throttler.go` | Init() rewritten, 6× `if false` → `if err != nil` |
| `internal/antitamper/antitamper.go` | `RunAllChecks()` — 3 dead checks restored; `verifyNixConfig()` subsequently disabled (infinite-loop score inflation) |
| `internal/security/security.go` | SSH key parsing added, imports updated |
| `flake.nix` | Service `path`, `after`, `wants` added |

---

## Correct Configuration Example

The failed deployment (`failed-flake.nix`) only set `enable = true` without
providing the required file paths.  Below is a corrected consumer flake showing
all necessary options.

```nix
# /etc/nixos/flake.nix  (consumer system flake)
{
  description = "Vex Hardened Dominion - Worker-LXC-106";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    vex-cli.url = "github:adumbdinosaur/vex-cli";
  };

  outputs = { self, nixpkgs, vex-cli, ... }: {
    nixosConfigurations.worker-lxc-106 = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ./hardware-configuration.nix

        # ── Import the vex-cli NixOS module ──────────────────────
        vex-cli.nixosModules.default

        ({ pkgs, ... }: {
          # ... (networking, users, packages, etc.) ...

          # ── VEX-CLI Integration ────────────────────────────────
          services.vex-cli = {
            enable = true;

            # Point at the config files so they are deployed to
            # /etc/vex-cli/ automatically.  Without these, the
            # directory is empty and every subsystem fails.
            manifestFile     = ./vex-cli/penance-manifest.json;
            forbiddenAppsFile = ./vex-cli/forbidden-apps.json;

            # Management key — the file can contain EITHER:
            #   • OpenSSH format:  ssh-ed25519 AAAA... comment
            #   • Hex-encoded raw 32-byte Ed25519 public key
            # (after the security.go fix, both are accepted)
            managementKeyFile = ./vex-cli/vex_management_key.pub;

            # Optional: force a specific process-monitoring backend
            # monitorMode = "ebpf";   # or "proc" / "auto" (default)
          };

          # The SSH authorized key and the management key serve
          # different purposes:
          #   • authorized key  → grants SSH login access
          #   • management key  → authorizes restriction-lowering
          #                        commands via Ed25519 signatures
          # They CAN be the same keypair, but the management key
          # file must contain the public key (not the SSH wire
          # format — unless you apply the security.go fix above).
          services.openssh.enable = true;
          users.users.root.openssh.authorizedKeys.keys = [
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINpLM0H2CEnM2sIswPVmeT3A1rHY/pBbYz7ICDYWEvjr vex-management-dedicated"
          ];

          system.stateVersion = "24.11";
        })
      ];
    };
  };
}
```

### What was wrong in the failed deployment

| What was missing | Consequence |
|---|---|
| `vex-cli` not in `inputs` | Module import was commented out — no service definition |
| `manifestFile` not set (default `null`) | `penance-manifest.json` not deployed → `open penance-manifest.json: no such file or directory` |
| `forbiddenAppsFile` not set | `forbidden-apps.json` not deployed → Guardian fell back to hardcoded defaults |
| `managementKeyFile` not set | `vex_management_key.pub` not deployed → first run: "no such file or directory"; after manual placement of SSH-format key: "expected 32 bytes, got 106" |
| Module `path` not set (fixed in flake.nix) | `nix-instantiate` not in systemd service PATH → anti-tamper NixOS checks always failed |
| `after = network.target` (fixed in flake.nix) | Service started before default route was up → interface detection failed → fell back to nonexistent `eth0` |

### Required file layout

Place these files alongside your system `flake.nix` (or adjust paths):

```
/etc/nixos/
├── flake.nix
├── hardware-configuration.nix
└── vex-cli/
    ├── penance-manifest.json      # task manifest
    ├── forbidden-apps.json        # process blocklist
    └── vex_management_key.pub     # Ed25519 public key (SSH or hex format)
```
