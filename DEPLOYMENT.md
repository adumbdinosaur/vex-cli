# vex-cli Deployment Guide

## Flake Architecture

The vex-cli project is now structured as a **pure flake** that can be imported as an input into downstream system configurations.

### Directory Structure

```
vex-cli/                     # This repository (pure vex-cli flake)
├── flake.nix                # Exports packages + nixosModules
├── cmd/vex-cli/main.go
├── internal/...
└── penance-manifest.json

vex-dominion/                # Your system configuration flake (separate repo)
├── flake.nix                # Imports vex-cli as input
├── hardware-configuration.nix
├── penance-manifest.json    # Config files for vex-cli
├── forbidden-apps.json
└── secrets/
    └── vex_management_key.pub
```

## Deployment Steps

### 1. Get the Correct vendorHash

First build attempt will show the hash:

```bash
cd vex-cli/
nix build .#vex-cli 2>&1 | grep 'got:'
```

Copy the hash from output like: `got:    sha256-ACTUAL_HASH_HERE`

Update line 26 in `flake.nix`:

```nix
vendorHash = "sha256-ACTUAL_HASH_HERE";
```

### 2. Create System Configuration Flake

See `vex-dominion-system-flake.nix` for a complete example.

Key sections:

```nix
inputs = {
  nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  
  # Import vex-cli as flake input
  vex-cli.url = "github:adumbdinosaur/vex-cli";  # or "path:../vex-cli"
  vex-cli.inputs.nixpkgs.follows = "nixpkgs";
};

outputs = { self, nixpkgs, vex-cli, ... }: {
  nixosConfigurations.worker-lxc-106 = nixpkgs.lib.nixosSystem {
    modules = [
      vex-cli.nixosModules.default  # Import the module
      
      ({ pkgs, ... }: {
        services.vex-cli = {
          enable = true;
          manifestFile = ./penance-manifest.json;
          forbiddenAppsFile = ./forbidden-apps.json;
          managementKeyFile = ./secrets/vex_management_key.pub;
        };
      })
    ];
  };
};
```

### 3. Generate Management Keypair

The Ed25519 keypair is used to sign restricted commands (unlock, throttle-off, etc):

```bash
# Generate keypair
ssh-keygen -t ed25519 -f vex_management_key -N "" -C "vex-management"

# The public key goes to the target system
cp vex_management_key.pub /etc/vex-cli/vex_management_key.pub

# Keep private key secure on management station
```

### 4. Deploy System Configuration

```bash
cd vex-dominion/
sudo nixos-rebuild switch --flake .#worker-lxc-106
```

### 5. Verify Service Status

```bash
sudo systemctl status vex-cli.service
sudo journalctl -u vex-cli.service -f
sudo vex-cli status
```

## Configuration Files

### penance-manifest.json

Defines available penance tasks:

```json
{
  "tasks": [
    {
      "id": "repent-001",
      "text": "I will not waste daylight hours on parasocial content.",
      "repetitions": 50,
      "validation": "daylight",
      "weight": 3,
      "kpm_threshold": 80,
      "allow_backspace": false
    }
  ]
}
```

### forbidden-apps.json

Process names and SNI domains to block:

```json
{
  "processes": ["steam", "Discord", "chrome"],
  "sni_domains": [
    "youtube.com",
    "reddit.com",
    "twitch.tv",
    "twitter.com",
    "x.com"
  ]
}
```

## CLI Usage

### Check Compliance Status

```bash
vex-cli status
```

### Complete Penance Task

```bash
# Select random task
vex-cli penance do

# Or specify task ID
vex-cli penance do repent-001
```

### Submit Completed Task

```bash
vex-cli penance submit <task-id> <your-typed-response-file>
```

### Unlock System (Requires Signature)

```bash
# On management station (has private key)
echo "unlock" | ssh-keygen -Y sign -f vex_management_key -n vex-cli > unlock.sig
scp unlock.sig worker:/tmp/

# On target system
vex-cli unlock /tmp/unlock.sig
```

### Apply Network Throttle (Requires Signature)

```bash
# Sign command
echo "throttle moderate 50" | ssh-keygen -Y sign -f vex_management_key -n vex-cli > throttle.sig

# Apply
vex-cli throttle moderate --entropy 50 --signature throttle.sig
```

## Security Model

- **Root-only service**: vex-cli runs as root with Linux capabilities
- **Append-only log**: /var/log/vex-cli.log with `chattr +a` immutability
- **Cryptographic signatures**: Ed25519 verification for restricted commands
- **Anti-tamper**: Periodic checks of service integrity and debugger detection. NixOS configuration integrity check is temporarily disabled (causes false-positive score inflation); will be re-enabled in a future release
- **Defense-in-depth**: SNI blocking + DNS sinkhole + process reaping

## Troubleshooting

### Service won't start

```bash
# Check systemd status
sudo systemctl status vex-cli.service

# View recent logs
sudo journalctl -u vex-cli.service -n 50

# Verify config files exist
ls -la /etc/vex-cli/
```

### Permission errors

vex-cli requires:
- CAP_NET_ADMIN (nftables, tc qdisc)
- CAP_SYS_RESOURCE (rlimit overrides)
- CAP_KILL (process termination)
- CAP_DAC_OVERRIDE (file access)
- CAP_LINUX_IMMUTABLE (chattr +a)

### Signature verification fails

Ensure:
1. Public key at `/etc/vex-cli/vex_management_key.pub`
2. Signature created with matching private key
3. Command string matches exactly (no extra whitespace)

```bash
# Debug signature
cat unlock.sig | base64 -d | hexdump -C
```

## Architecture Notes

### Why separate flakes?

1. **Versioning**: Pin vex-cli version in flake.lock
2. **Reusability**: Import into multiple system configs
3. **CI/CD**: Build/test vex-cli independently
4. **Nix conventions**: Standard pattern for nixosModules

### Flake inputs locking

When you run `nix flake update`, it updates `flake.lock` with exact commits:

```bash
# Update all inputs
nix flake update

# Update only vex-cli
nix flake lock --update-input vex-cli
```

This ensures reproducible builds across deployments.

## Development Workflow

### Local development

```bash
cd vex-cli/
go build -o vex-cli ./cmd/vex-cli/
sudo ./vex-cli status
```

### Test Nix build

```bash
nix build .#vex-cli
./result/bin/vex-cli --version
```

### Test in VM

```bash
cd vex-dominion/
nixos-rebuild build-vm --flake .#worker-lxc-106
./result/bin/run-worker-lxc-106-vm
```

### CI Integration

Example GitHub Actions workflow:

```yaml
name: Build vex-cli
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: cachix/install-nix-action@v22
        with:
          extra_nix_config: |
            experimental-features = nix-command flakes
      - run: nix flake check
      - run: nix build .#vex-cli
      - run: nix build .#packages.x86_64-linux.vex-cli
```

## eBPF Process Monitoring

vex-cli supports two process monitoring backends:

### 1. /proc Polling (Default, Always Available)

Scans `/proc` every 2 seconds to detect and terminate forbidden processes. Works on any kernel version.

### 2. eBPF Tracepoint (High-Performance, Optional)

Attaches to the `sched:sched_process_exec` kernel tracepoint for real-time process detection with zero polling overhead.

**Requirements:**
- Linux kernel 4.15+ (for tracepoint support)
- Linux kernel 5.8+ (for CAP_BPF and CAP_PERFMON capabilities)
- clang, llvm (for eBPF compilation)
- libbpf headers

**Enabling eBPF:**

The NixOS module automatically tries eBPF first and falls back to /proc polling:

```nix
services.vex-cli = {
  enable = true;
  monitorMode = "auto";  # Try eBPF, fallback to /proc (default)
  # monitorMode = "ebpf"; # Force eBPF, fail if unavailable
  # monitorMode = "proc"; # Force /proc polling
};
```

**Building with eBPF:**

The flake already includes eBPF build dependencies and capabilities. To generate the eBPF bytecode:

```bash
cd vex-cli/
nix-shell  # Provides clang, llvm, libbpf
go generate ./internal/guardian
```

This compiles `execmon.bpf.c` and generates Go bindings (`ebpf_bpfel.go`, `ebpf_bpfeb.go`).

**Current Status:**

The eBPF infrastructure is scaffolded with:
- ✅ C eBPF program ([internal/guardian/execmon.bpf.c](internal/guardian/execmon.bpf.c))
- ✅ Go wrapper ([internal/guardian/ebpf_monitor.go](internal/guardian/ebpf_monitor.go))
- ✅ Build tags (`-tags ebpf` to enable)
- ✅ NixOS module support (CAP_BPF, CAP_PERFMON capabilities)
- ⚠️ Needs `go generate` to compile eBPF bytecode
- ✅ Graceful fallback to /proc if eBPF fails

**Verifying the Backend:**

```bash
sudo systemctl status vex-cli.service
sudo journalctl -u vex-cli.service | grep "Guardian:"

# Look for one of:
# "Guardian: Using eBPF-based process monitoring (high-performance mode)"
# "Guardian: Falling back to /proc polling"
```

Or via CLI:

```bash
sudo vex-cli status
# Shows monitoring backend in output
```

