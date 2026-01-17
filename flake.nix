{
  # Human-readable description of what this flake does
  description = "NixForge - Secure Manager Node with k3s";

  # External dependencies (inputs) the flake uses
  inputs = {
    # NixOS packages (unstable branch for latest features)
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    # Disko for declarative disk partitioning
    disko.url = "github:nix-community/disko";
    disko.inputs.nixpkgs.follows = "nixpkgs";

    # sops-nix for managing encrypted secrets
    sops-nix.url = "github:Mic92/sops-nix";
    sops-nix.inputs.nixpkgs.follows = "nixpkgs";

    # nix-darwin for macOS builder VM
    darwin.url = "github:LnL7/nix-darwin";
    darwin.inputs.nixpkgs.follows = "nixpkgs";

    # Colmena for deploying to the server
    colmena.url = "github:zhaofengli/colmena";
    colmena.inputs.nixpkgs.follows = "nixpkgs";
  };

  # Outputs produced by this flake
  outputs = { self, nixpkgs, disko, sops-nix, darwin, colmena, ... }@inputs: {
    # NixOS config for the manager server
    nixosConfigurations.manager = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";  # Target architecture

      modules = [
        disko.nixosModules.disko              # Enable disko module
        sops-nix.nixosModules.sops            # Enable sops-nix module

        # Main system configuration
        ({ config, pkgs, ... }: {
          nix.settings.experimental-features = [ "nix-command" "flakes" ];  # Enable flakes and new CLI

          boot.loader.systemd-boot.enable = true;  # Use systemd-boot bootloader
          boot.loader.efi.canTouchEfiVariables = true;  # Allow EFI variable changes

          # Declarative disk layout (disko)
          disko.devices = {
            disk.main = {
              type = "disk";
              device = "/dev/nvme0n1";  # Your first NVMe drive
              content = {
                type = "gpt";  # GPT partition table
                partitions = {
                  ESP = {  # EFI System Partition
                    type = "EF00";
                    size = "512M";
                    content = {
                      type = "filesystem";
                      format = "vfat";
                      mountpoint = "/boot";
                    };
                  };
                  root = {  # Main root partition
                    size = "100%";
                    content = {
                      type = "filesystem";
                      format = "btrfs";
                      extraArgs = [ "-L" "nixos" ];
                      subvolumes = {
                        "/" = { mountpoint = "/"; };           # Root subvolume
                        "/nix" = { mountpoint = "/nix"; };     # Nix store
                        "/persist" = { mountpoint = "/persist"; };  # Persistent data
                      };
                    };
                  };
                };
              };
            };
          };

          # Network settings
          networking = {
            hostName = "manager";  # Hostname of the server
            interfaces.enp10s0f1np1.ipv4.addresses = [{  # Static IP config
              address = "69.164.248.38";
              prefixLength = 30;
            }];
            defaultGateway = "69.164.248.37";  # Gateway IP
            nameservers = [ "8.8.8.8" "1.1.1.1" ];  # DNS servers
          };

          # Firewall - only open necessary ports
          networking.firewall = {
            enable = true;
            allowedTCPPorts = [ 22 6443 80 443 ];  # SSH, k3s API, HTTP/HTTPS
          };

          # SSH server configuration
          services.openssh = {
            enable = true;
            settings = {
              PasswordAuthentication = false;  # Disable password login
              PermitRootLogin = "prohibit-password";  # Disable root password login
              KbdInteractiveAuthentication = false;  # Disable keyboard-interactive
            };
          };

          # Root user SSH keys
          users.users.root.openssh.authorizedKeys.keys = [
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE4qb5fQCQ5ZuyRyAKLD81yu12X2Mov0qePbpBwFwAaD"
          ];

          # Non-root user 'ruud' for daily use
          users.users.ruud = {
            isNormalUser = true;
            extraGroups = [ "wheel" "libvirtd" ];  # sudo + libvirt access
            openssh.authorizedKeys.keys = [
              "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE4qb5fQCQ5ZuyRyAKLD81yu12X2Mov0qePbpBwFwAaD"
            ];
          };

          security.sudo = {
            enable = true;
            wheelNeedsPassword = false;  # sudo without password for wheel group
          };

          # sops-nix for secrets
          sops = {
            age.keyFile = "/var/lib/sops-nix/key.txt";  # Path to age key
            defaultSopsFile = ./secrets/secrets.yaml;   # Default encrypted file
          };

          # k3s Kubernetes cluster
          services.k3s = {
            enable = true;
            role = "server";  # Control plane node
            clusterInit = true;  # Initialize cluster
            extraFlags = "--disable=traefik --kube-apiserver-arg=audit-log-path=/var/log/k3s/audit.log";
          };

          # Libvirt for virtual machines
          virtualisation.libvirtd.enable = true;
          programs.virt-manager.enable = true;
          users.users.root.extraGroups = [ "libvirtd" ];

          # Podman for Docker-compatible containers
          virtualisation.podman = {
            enable = true;
            dockerCompat = true;  # Make podman act like docker
            defaultNetwork.settings.dns_enabled = true;
          };

          # Useful system packages
          environment.systemPackages = with pkgs; [
            kubectl k9s helm curl git fail2ban bandwhich restic podman-compose
          ];

          # Fail2ban for brute-force protection
          services.fail2ban.enable = true;

          # Automatic system updates (no reboot)
          system.autoUpgrade = {
            enable = true;
            allowReboot = false;
          };

          # Kernel hardening parameters
          boot.kernel.sysctl = {
            "kernel.unprivileged_bpf_disabled" = 1;
            "net.core.bpf_jit_enable" = 0;
          };

          # NixOS state version - NEVER change after first install
          system.stateVersion = "25.05";
        })
      ];
    };

    # macOS builder config (for cross-compiling)
    darwinConfigurations.builder = darwin.lib.darwinSystem {
      system = "aarch64-darwin";
      modules = [ ./darwin-configuration.nix ];
    };

    # Colmena deployment configuration
    colmena = {
      meta = {
        nixpkgs = import nixpkgs { system = "x86_64-linux"; };
        specialArgs = { inherit inputs; };
      };

      defaults = { deployment.targetUser = "root"; };

      manager = {
        deployment.targetHost = "69.164.248.38";
        imports = [ self.nixosConfigurations.manager ];
      };
    };
  };
}