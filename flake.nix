{
  # Human-readable description of what this flake does
  description = "NixForge - Secure Manager Node with k3s";

  # External dependencies (inputs)
  inputs = {
    # Main NixOS package set - using unstable for latest Rust/k3s versions
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    # Disko - declarative disk partitioning
    disko.url = "github:nix-community/disko";
    disko.inputs.nixpkgs.follows = "nixpkgs";

    # sops-nix - secrets management
    sops-nix.url = "github:Mic92/sops-nix";
    sops-nix.inputs.nixpkgs.follows = "nixpkgs";

    # nix-darwin - macOS configuration
    darwin.url = "github:LnL7/nix-darwin";
    darwin.inputs.nixpkgs.follows = "nixpkgs";

    # Colmena - remote deployment tool
    colmena.url = "github:zhaofengli/colmena";
    colmena.inputs.nixpkgs.follows = "nixpkgs";
  };

  # The outputs function produces the actual configurations
  outputs = { self, nixpkgs, disko, sops-nix, darwin, colmena, ... }@inputs:
    let
      # Define the architecture for the remote server
      system = "x86_64-linux";

      # === FIX: Define the Shared Module List ===
      # We define the configuration here so we can reuse it in both
      # 'nixosConfigurations' and 'colmena'.
      managerModules = [
        # 1. Import Disko module for disk partitioning
        disko.nixosModules.disko
        # 2. Import Sops module for secret management
        sops-nix.nixosModules.sops
        
        # 3. The Main Server Configuration
        ({ config, pkgs, ... }: {
          # Enable flakes and modern nix commands
          nix.settings.experimental-features = [ "nix-command" "flakes" ];

          # Bootloader: Use systemd-boot for UEFI
          boot.loader.systemd-boot.enable = true;
          boot.loader.efi.canTouchEfiVariables = true;

          # === DISK LAYOUT (Disko) ===
          disko.devices = {
            disk.main = {
              type = "disk";
              device = "/dev/nvme0n1"; # Primary NVMe
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
                        "/" = { mountpoint = "/"; };
                        "/nix" = { mountpoint = "/nix"; };
                        "/persist" = { mountpoint = "/persist"; };
                      };
                    };
                  };
                };
              };
            };
          };

          # === NETWORKING ===
          networking = {
            hostName = "manager";
            # Static IP provided by InterServer
            interfaces.enp10s0f1np1.ipv4.addresses = [{
              address = "69.164.248.38";
              prefixLength = 30;
            }];
            defaultGateway = "69.164.248.37";
            nameservers = [ "8.8.8.8" "1.1.1.1" ];
            
            # Firewall: Open essential ports
            firewall = {
              enable = true;
              allowedTCPPorts = [ 
                22    # SSH
                6443  # k3s API
                80    # HTTP
                443   # HTTPS
              ]; 
            };
          };

          # === SECURITY & USERS ===
          # SSH Hardening
          services.openssh = {
            enable = true;
            settings = {
              PasswordAuthentication = false;
              PermitRootLogin = "prohibit-password";
              KbdInteractiveAuthentication = false;
            };
          };

          # Root User
          users.users.root.openssh.authorizedKeys.keys = [
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE4qb5fQCQ5ZuyRyAKLD81yu12X2Mov0qePbpBwFwAaD"
          ]; 

          # Admin User (ruud)
          users.users.ruud = {
            isNormalUser = true;
            extraGroups = [ "wheel" "libvirtd" "docker" ]; # Added docker group for podman socket access
            openssh.authorizedKeys.keys = [
              "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE4qb5fQCQ5ZuyRyAKLD81yu12X2Mov0qePbpBwFwAaD"
            ];
          };

          # Sudo (Passwordless for Wheel group for easier automation)
          security.sudo = {
            enable = true;
            wheelNeedsPassword = false;
          };

          # Secrets Management (Sops)
          sops = {
            age.keyFile = "/var/lib/sops-nix/key.txt";
            defaultSopsFile = ./secrets/secrets.yaml;
            # secrets.example_secret = {}; # Uncomment when you have secrets
          };

          # === SERVICES: K3s (Kubernetes) ===
          services.k3s = {
            enable = true;
            role = "server";
            clusterInit = true;
            # Secure configuration: Disable default traefik to manage it manually later
            extraFlags = "--disable=traefik --kube-apiserver-arg=audit-log-path=/var/log/k3s/audit.log";
          };

          # === VIRTUALIZATION ===
          # Libvirt / Virt-Manager
          virtualisation.libvirtd.enable = true;
          programs.virt-manager.enable = true;
          users.users.root.extraGroups = [ "libvirtd" ];

          # Podman (Docker replacement)
          virtualisation.podman = {
            enable = true;
            dockerCompat = true; # Aliases docker -> podman
            defaultNetwork.settings.dns_enabled = true;
          };

          # === PACKAGES ===
          environment.systemPackages = with pkgs; [
            # Kubernetes Tools
            kubectl
            k9s
            helm
            
            # Utilities
            curl
            git
            wget
            htop
            
            # Security & Backup
            fail2ban
            restic
            
            # Rust/Dev Tools
            bandwhich      # Bandwidth monitor (Rust)
            podman-compose
            ripgrep        # Grep alternative (Rust)
          ];

          # Fail2Ban (Intrusion prevention)
          services.fail2ban.enable = true;

          # Auto-Updates (Security patches)
          system.autoUpgrade = {
            enable = true;
            allowReboot = false;
          };

          # Kernel Hardening
          boot.kernel.sysctl = {
            "kernel.unprivileged_bpf_disabled" = 1;
            "net.core.bpf_jit_enable" = 0;
          };

          # State Version (Do not change this after install)
          system.stateVersion = "25.05";
        })
      ];

    in {
      # === 1. Standard NixOS Configuration ===
      # Used by 'nixos-rebuild' directly or 'nix flake check'
      nixosConfigurations.manager = nixpkgs.lib.nixosSystem {
        system = system;
        modules = managerModules; # Uses the shared list defined above
      };

      # === 2. MacOS Builder Configuration ===
      darwinConfigurations.builder = darwin.lib.darwinSystem {
        system = "aarch64-darwin";
        modules = [ 
          # Inline module for completeness - you can replace this with ./darwin-configuration.nix
          ({ pkgs, ... }: {
             # Minimal config to make the flake valid
             nix.settings.experimental-features = [ "nix-command" "flakes" ];
             services.nix-daemon.enable = true;
             system.stateVersion = 6;
          })
        ];
      };

      # === 3. Colmena Deployment Configuration ===
      colmena = {
        meta = {
          # Use the same nixpkgs for consistency
          nixpkgs = import nixpkgs { 
            system = "x86_64-linux"; 
          };
          # Pass inputs to modules if needed
          specialArgs = { inherit inputs; };
        };

        defaults = { 
          # Deployment settings common to all nodes
          deployment.targetUser = "root"; 
          
          # CRITICAL for macOS -> Linux deployment:
          # This forces the build to happen on the remote server (Dallas)
          # instead of trying to cross-compile on your Mac.
          deployment.buildOnTarget = true;
        };

        manager = {
          deployment.targetHost = "69.164.248.38";
          # Here is where we use the variable that caused the error
          imports = managerModules; 
        };
      };
    };
}