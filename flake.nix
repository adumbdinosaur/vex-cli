{
  description = "VEX-CLI - Kernel-integrated administration and disciplinary interface (Protocol 106-V)";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs, ... }:
  let
    system = "x86_64-linux";
    pkgs = nixpkgs.legacyPackages.${system};

    # Common build attributes shared by both packages
    commonAttrs = {
      version = "2.0-V";
      src = self;
      vendorHash = null;
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

      ldflags = [
        "-s" "-w"
        "-X github.com/adumbdinosaur/vex-cli/internal/antitamper.ExpectedBinaryHash=SET_AT_RUNTIME"
      ];
    };

    # ── vexd: the enforcement daemon ────────────────────────────────
    vexd = pkgs.buildGoModule (commonAttrs // {
      pname = "vexd";
      subPackages = [ "cmd/vexd" ];
      meta = {
        description = "VEX enforcement daemon (Protocol 106-V)";
        mainProgram = "vexd";
      };
    });

    # ── vex-cli: thin control-plane client ──────────────────────────
    vex-cli = pkgs.buildGoModule (commonAttrs // {
      pname = "vex-cli";
      subPackages = [ "cmd/vex-cli" ];
      meta = {
        description = "VEX-CLI control plane (Protocol 106-V)";
        mainProgram = "vex-cli";
      };
    });

  in {
    # ── Expose packages ─────────────────────────────────────────────
    packages.${system} = {
      inherit vexd vex-cli;
      default = vexd;
    };

    # ── NixOS module ────────────────────────────────────────────────
    nixosModules.default = { config, lib, pkgs, ... }:
    let
      cfg = config.services.vex-cli;
    in {
      options.services.vex-cli = {
        enable = lib.mkEnableOption "VEX-CLI enforcement daemon";

        daemonPackage = lib.mkOption {
          type = lib.types.package;
          default = vexd;
          description = "The vexd daemon package to use.";
        };

        cliPackage = lib.mkOption {
          type = lib.types.package;
          default = vex-cli;
          description = "The vex-cli control-plane package to use.";
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

        # ── systemd service: vexd daemon ────────────────────────────────
        systemd.services.vexd = {
          description = "VEX Enforcement Daemon (Protocol 106-V)";
          wantedBy = [ "multi-user.target" ];
          after = [ "network-online.target" "systemd-resolved.service" ];
          wants = [ "network-online.target" ];

          # Ensure Nix CLI tools and coreutils are in PATH for anti-tamper checks
          path = with pkgs; [ nix coreutils systemd ];

          serviceConfig = {
            Type = "simple";
            ExecStart = "${cfg.daemonPackage}/bin/vexd";
            WorkingDirectory = "/etc/vex-cli";
            Restart = "always";
            RestartSec = 5;
            
            Environment = [
              "VEX_MONITOR_MODE=${cfg.monitorMode}"
            ];

            # ── Root + capabilities ──────────────────────────────────
            User = "root";
            Group = "root";

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
            ProtectSystem = "full";
            ProtectHome = true;
            NoNewPrivileges = true;
            LockPersonality = true;
            ProtectClock = true;
            ProtectKernelModules = true;
            RestrictRealtime = true;

            ReadWritePaths = [
              "/var/log"                # logging
              "/var/lib/vex-cli"        # persisted system state
              "/run/vex-cli"            # Unix domain socket
              "/sys/fs/cgroup"          # CPU governance
              "/etc/vex-cli"            # compliance-status.json updates
            ];

            RuntimeDirectory = "vex-cli";        # creates /run/vex-cli
            StateDirectory = "vex-cli";           # creates /var/lib/vex-cli

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
            ExecStart = "${cfg.cliPackage}/bin/vex-cli check";
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

        # Make both binaries available system-wide
        environment.systemPackages = [ cfg.daemonPackage cfg.cliPackage ];
      };
    };

    # Legacy alias for backwards compatibility
    nixosModules.vex-cli = self.nixosModules.default;
  };
}
