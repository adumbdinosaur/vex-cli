{
  description = "Vex Hardened Dominion - Worker-LXC-106";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
#    vex-cli.url = "git+file:///home/toy/vex-cli";
  };

  outputs = { self, nixpkgs, ... }@inputs: {
    nixosConfigurations.worker-lxc-106 = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ./hardware-configuration.nix
 #       vex-cli.nixosModules.default
        ({ pkgs, ... }: 
        let
          pythonEnv = pkgs.python3.withPackages (ps: [ ps.evdev ]);
        in
        {
          networking.hostName = "worker-lxc-106";
          nix.settings.experimental-features = [ "nix-command" "flakes" ];
          nixpkgs.config.allowUnfree = true;
          boot.loader.systemd-boot.enable = true;
          boot.loader.efi.canTouchEfiVariables = true;

          networking.hosts = {
            "127.0.0.1" = [ 
              "youtube.com" "www.youtube.com" 
              "reddit.com" "www.reddit.com"
              "twitter.com" "x.com" 
              "twitch.tv" "bsky.app"
              "facebook.com" "instagram.com" "tiktok.com"
            ];
          };

          users.users.toy = {
            isNormalUser = true;
            extraGroups = [ "networkmanager" "wheel" "video" "input" ];
            initialPassword = "toy";
          };

          environment.interactiveShellInit = ''
            export PS1="toy@FAILURE:$ "
          '';

          environment.systemPackages = with pkgs; [
            git vim wget curl htop sway foot waybar swaybg wofi firefox neovim nchat fira-code nmap ffmpeg imv mpv pythonEnv steam-run telegram-desktop vscode discord
          ];

          programs.sway.enable = true;
          programs.steam = {
            enable = true;
            remotePlay.openFirewall = true;
            dedicatedServer.openFirewall = true;
          };

          hardware.graphics = {
            enable = true;
            enable32Bit = true;
          };

          environment.etc."sway/config".source = ./sway-config;

          # ── VEX-CLI Integration ──────────────────────────────────
          #services.vex-cli = {
          #  enable = true;
          #};

          # Legacy surveillance (Vex-CLI surveillance is enabled in service above)
          systemd.services.vex-surveillance.enable = false;

          services.openssh.enable = true;
          services.openssh.settings.PermitRootLogin = "yes";
          users.users.root.openssh.authorizedKeys.keys = [
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBr6+X9vT9+C8zUqfG2q1pG7sN9O7v+e7mU5bL2F1X9X vex-agent"
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINpLM0H2CEnM2sIswPVmeT3A1rHY/pBbYz7ICDYWEvjr vex-management-dedicated"
          ];

          system.stateVersion = "24.11";
        })
      ];
    };
  };
}
