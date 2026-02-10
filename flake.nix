{
  description = "VEX-CLI - Kernel-integrated administration and disciplinary interface (Protocol 106-V)";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs, ... }:
  let
    system = "x86_64-linux";
    pkgs = nixpkgs.legacyPackages.${system};

    # ── vex-cli Go package ──────────────────────────────────────────
    vex-cli = pkgs.buildGoModule {
      pname = "vex-cli";
      version = "1.06-V";

      # Source is the repo root (this flake).
      # In production you'd point at a pinned ref; locally "self" works.
      src = self;

      # After the first build, nix will tell you the real hash.
      # Run:  nix build .#vex-cli
      # The error output will contain 'got: sha256-XXXX'. Paste that here.
      # Alternatively: cd into repo, run `go mod vendor`, commit vendor/,
      # and set vendorHash = null;
      vendorHash = null;

      # Only build the CLI entry-point
      subPackages = [ "cmd/vex-cli" ];

      # CGo is needed for evdev / nftables C deps
      # eBPF requires clang, llvm, and kernel headers
      env.CGO_ENABLED = 1;

      nativeBuildInputs = with pkgs; [ 
        pkg-config 
        gcc 
        clang
        llvm
        elfutils
      ];
      buildInputs = with pkgs; [ 
        libnftnl 
        libmnl 
        libevdev 
        linuxHeaders
      ];

      # Tags for optional eBPF support
      # Build will work without eBPF but fall back to /proc polling
      tags = [ "ebpf" ];

      # Embed the expected binary hash at build time for self-verification
      ldflags = [
        "-s" "-w"
        "-X github.com/adumbdinosaur/vex-cli/internal/antitamper.ExpectedBinaryHash=37bd5d4e6563535266e5948dcc91db2eea40148fc1221c0f69cf542be53f4e08"
      ];

      meta = {
        description = "VEX-CLI enforcement engine (Protocol 106-V)";
        mainProgram = "vex-cli";
      };
    };

  in {
    # ── Expose the package ──────────────────────────────────────────
    packages.${system} = {
      inherit vex-cli;
      default = vex-cli;
    };

    # ── NixOS module ────────────────────────────────────────────────
    nixosModules.default = { config, lib, pkgs, ... }:
    let
      cfg = config.services.vex-cli;
    in {
      options.services.vex-cli = {
        enable = lib.mkEnableOption "VEX-CLI enforcement daemon";

        package = lib.mkOption {
          type = lib.types.package;
          default = vex-cli;
          description = "The vex-cli package to use.";
        };

        configDir = lib.mkOption {
          type = lib.types.path;
          default = /etc/vex-cli;
          description = "Directory containing penance-manifest.json, forbidden-apps.json, and management key.";
        };

        manifestFile = lib.mkOption {
          type = lib.types.nullOr lib.types.path;
          default = null;
          description = "Path to penance-manifest.json. If null, you must provide it at /etc/vex-cli/ manually.";
        };

        forbiddenAppsFile = lib.mkOption {
          type = lib.types.nullOr lib.types.path;
          default = null;
          description = "Path to forbidden-apps.json. If null, you must provide it at /etc/vex-cli/ manually.";
        };

        managementKeyFile = lib.mkOption {
          type = lib.types.nullOr lib.types.path;
          default = null;
          description = "Path to the Ed25519 public key file for command authorization.";
        };

        monitorMode = lib.mkOption {
          type = lib.types.enum [ "ebpf" "proc" "auto" ];
          default = "auto";
          description = ''
            Process monitoring backend:
            - "ebpf": Use eBPF tracepoint for high-performance monitoring (requires kernel 4.15+)
            - "proc": Use /proc polling (fallback, works on any kernel)
            - "auto": Try eBPF first, fallback to /proc if eBPF fails
          '';
        };
      };

      config = lib.mkIf cfg.enable {

        # ── Deploy config files to /etc/vex-cli/ ───────────────────
        environment.etc = lib.mkMerge [
          (lib.mkIf (cfg.manifestFile != null) {
            "vex-cli/penance-manifest.json" = {
              source = cfg.manifestFile;
              mode = "0644";
            };
          })
          (lib.mkIf (cfg.forbiddenAppsFile != null) {
            "vex-cli/forbidden-apps.json" = {
              source = cfg.forbiddenAppsFile;
              mode = "0644";
            };
          })
          (lib.mkIf (cfg.managementKeyFile != null) {
            "vex-cli/vex_management_key.pub" = {
              source = cfg.managementKeyFile;
              mode = "0400";
            };
          })
        ];

        # ── systemd service: vex-cli daemon ─────────────────────────
        systemd.services.vex-cli = {
          description = "VEX-CLI Enforcement Daemon (Protocol 106-V)";
          wantedBy = [ "multi-user.target" ];
          after = [ "network.target" "systemd-resolved.service" ];

          # The binary reads config from its working directory;
          # symlink /etc/vex-cli contents or set WorkingDirectory.
          serviceConfig = {
            Type = "simple";
            ExecStart = "${cfg.package}/bin/vex-cli init";
            WorkingDirectory = "/etc/vex-cli";
            Restart = "always";
            RestartSec = 5;
            
            # Environment variables
            Environment = [
              "VEX_MONITOR_MODE=${cfg.monitorMode}"
            ];

            # ── Root + capabilities ──────────────────────────────────
            # Must run as root for cgroups, nftables, /dev/input, oom_score_adj
            User = "root";
            Group = "root";

            # Grant fine-grained caps even though running as root,
            # so we're explicit about what is required:
            AmbientCapabilities = [
              "CAP_NET_ADMIN"       # tc / nftables
              "CAP_SYS_RESOURCE"    # oom_score_adj, cgroups
              "CAP_KILL"            # process reaper (SIGKILL forbidden apps)
              "CAP_DAC_OVERRIDE"    # read /dev/input, /proc/*/comm
              "CAP_LINUX_IMMUTABLE" # chattr +a on log file
              "CAP_BPF"             # eBPF program loading (kernel 5.8+)
              "CAP_PERFMON"         # eBPF perf events (kernel 5.8+)
            ];

            # ── Hardening ────────────────────────────────────────────
            ProtectSystem = "full";       # /usr, /boot read-only
            ProtectHome = true;           # hide /home from daemon
            NoNewPrivileges = true;
            LockPersonality = true;
            ProtectClock = true;
            ProtectKernelModules = true;
            RestrictRealtime = true;

            # Read-write paths the daemon actually needs
            ReadWritePaths = [
              "/var/log"                # logging
              "/sys/fs/cgroup"          # CPU governance
              "/etc/vex-cli"            # compliance-status.json updates
            ];

            # Access to input devices for evdev surveillance
            SupplementaryGroups = [ "input" ];
            DeviceAllow = [ "/dev/input/* rw" ];
          };
        };

        # ── systemd service: vex-cli anti-tamper timer ──────────────
        # Separate oneshot for periodic integrity checks (belt + suspenders
        # on top of the in-process monitor, survives daemon restarts)
        systemd.services.vex-cli-integrity = {
          description = "VEX-CLI Integrity Check";
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${cfg.package}/bin/vex-cli check";
            WorkingDirectory = "/etc/vex-cli";
            User = "root";
          };
        };

        systemd.timers.vex-cli-integrity = {
          description = "VEX-CLI Periodic Integrity Check";
          wantedBy = [ "timers.target" ];
          timerConfig = {
            OnBootSec = "2min";
            OnUnitActiveSec = "5min";
            Persistent = true;
          };
        };

        # ── Log file setup: create and set append-only ──────────────
        systemd.tmpfiles.rules = [
          "f /var/log/vex-cli.log 0644 root root - -"
        ];

        # Make vex-cli available system-wide for manual commands
        environment.systemPackages = [ cfg.package ];
      };
    };

    # Legacy alias for backwards compatibility
    nixosModules.vex-cli = self.nixosModules.default;
  };
}
