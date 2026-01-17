{
  # Human-readable description of what this flake does
  description = "NixForge - Secure Manager Node with k3s";

  # External dependencies (inputs) the flake uses
  inputs = {
    # Main NixOS package set - using the unstable branch for latest features
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    # Disko - tool for declarative disk partitioning
    disko.url = "github:nix-community/disko";
    # Make sure disko uses the same nixpkgs version as we do
    disko.inputs.nixpkgs.follows = "nixpkgs";

    # sops-nix for secrets management
    sops-nix.url = "github:Mic92/sops-nix";
    sops-nix.inputs.nixpkgs.follows = "nixpkgs";

    # nix-darwin for macOS builder
    darwin.url = "github:LnL7/nix-darwin";
    darwin.inputs.nixpkgs.follows = "nixpkgs";

    # Colmena for deployment
    colmena.url = "github:zhaofengli/colmena";
    colmena.inputs.nixpkgs.follows = "nixpkgs";
  };

  # What this flake produces (outputs)
  outputs = { self, nixpkgs, disko, sops-nix, darwin, colmena, ... }@inputs: {
    # NixOS configuration for the manager server
    nixosConfigurations.manager = nixpkgs.lib.nixosSystem {
      # Target architecture (standard 64-bit Intel/AMD)
      system = "x86_64-linux";

      # List of modules that together define the system
      modules = [
        # Include the disko module so we can use declarative disk config
        disko.nixosModules.disko
        # Include sops-nix for encrypted secrets
        sops-nix.nixosModules.sops

        # Main configuration (anonymous module)
        ({ config, pkgs, ... }: {
          # Enable modern nix features we need
          nix.settings.experimental-features = [ "nix-command" "flakes" ];

          # Bootloader configuration for UEFI systems
          boot.loader.systemd-boot.enable = true;
          boot.loader.efi.canTouchEfiVariables = true;

          # === DISK LAYOUT (disko) - NO LUKS for first install ===
          disko.devices = {
            disk.main = {
              type = "disk";
              device = "/dev/nvme0n1";  # ← CHANGE if using nvme1n1
              content = {
                type = "gpt";
                partitions = {
                  ESP = {
                    type = "EF00";
                    size = "512M";
                    content = {
                      type = "filesystem";
                      format = "vfat";
                      mountpoint = "/boot";
                    };
                  };
                  root = {
                    size = "100%";
                    content = {
                      type = "filesystem";
                      format = "btrfs";
                      extraArgs = [ "-L" "nixos" ];
                      subvolumes = {
                        "/" = {
                          mountpoint = "/";
                        };
                        "/nix" = {
                          mountpoint = "/nix";
                        };
                        "/persist" = {
                          mountpoint = "/persist";
                        };
                      };
                    };
                  };
                };
              };
            };
          };

          # Basic network config
          networking = {
            hostName = "manager";
            # Static IP from InterServer
            interfaces.enp10s0f1np1.ipv4.addresses = [{
              address = "69.164.248.38";
              prefixLength = 30;
            }];
            defaultGateway = "69.164.248.37";
            nameservers = [ "8.8.8.8" "1.1.1.1" ];
          };

          # Firewall: Allow SSH, k3s API, and HTTP/HTTPS for future ingress
          networking.firewall = {
            enable = true;
            allowedTCPPorts = [ 22 6443 80 443 ];
          };

          # SSH hardening
          services.openssh = {
            enable = true;
            settings = {
              PasswordAuthentication = false;
              PermitRootLogin = "prohibit-password";
              KbdInteractiveAuthentication = false;
            };
          };

          # ← CHANGE: paste your public SSH key here (from 1Password)
          users.users.root.openssh.authorizedKeys.keys = [
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE4qb5fQCQ5ZuyRyAKLD81yu12X2Mov0qePbpBwFwAaD"
          ]; 
          users.users.ruud = {
            isNormalUser = true;
            extraGroups = [ "wheel" "libvirtd" ];
            openssh.authorizedKeys.keys = [
              "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE4qb5fQCQ5ZuyRyAKLD81yu12X2Mov0qePbpBwFwAaD"  # Same as root
            ];
          };

          security.sudo = {
            enable = true;
            wheelNeedsPassword = false;
          };

          # sops secrets (example: add your age key)
          sops = {
            age.keyFile = "/var/lib/sops-nix/key.txt";  # Generate with age-keygen
            defaultSopsFile = ./secrets/secrets.yaml;   # Encrypted file
          };

          # === k3s Kubernetes (lightweight distro) ===
          services.k3s = {
            enable = true;              # Turn on k3s
            role = "server";            # This node will be a control-plane
            clusterInit = true;         # Initialize a new single-node cluster
            extraFlags = "--disable=traefik --kube-apiserver-arg=audit-log-path=/var/log/k3s/audit.log";  # Secure extras: disable defaults, enable audit
          };

          # VMs (libvirt + virt-manager)
          virtualisation.libvirtd.enable = true;
          programs.virt-manager.enable = true;
          users.users.root.extraGroups = [ "libvirtd" ];

          # Docker-compatible containers via Podman (declarative, git-friendly)
          virtualisation.podman = {
            enable = true;
            dockerCompat = true;
            defaultNetwork.settings.dns_enabled = true;
          };

          # Security tools
          environment.systemPackages = with pkgs; [
            kubectl      # Kubernetes CLI
            k9s          # Terminal UI for Kubernetes
            helm         # Package manager for Kubernetes
            curl
            git
            fail2ban     # Brute-force protection
            bandwhich    # Rust-based net inspector
            restic       # Rust-based encrypted backups
            podman-compose   # for version-controlled podman-compose.yml files
          ];

          # Fail2ban config (jails for SSH, k3s API)
          services.fail2ban.enable = true;

          # Auto-updates
          system.autoUpgrade = {
            enable = true;
            allowReboot = false;
          };

          # Kernel hardening
          boot.kernel.sysctl = {
            "kernel.unprivileged_bpf_disabled" = 1;
            "net.core.bpf_jit_enable" = 0;
          };

          # NixOS state version - do NOT change after first install
          system.stateVersion = "25.05";
        })
      ];
    };

    # macOS builder configuration
    darwinConfigurations.builder = darwin.lib.darwinSystem {
      system = "aarch64-darwin";
      modules = [ ./darwin-configuration.nix ];
    };

    # Colmena deployment hive - Colmena reads this attribute directly
    colmena = {
      meta = {
        nixpkgs = import nixpkgs { system = "x86_64-linux"; };
        specialArgs = { inherit inputs; };
      };

      defaults = { deployment.targetUser = "root"; };

      manager = {
        deployment.targetHost = "69.164.248.38";
        imports = self.nixosConfigurations.manager.config.system.build.modules;
      };
    };
  };
}