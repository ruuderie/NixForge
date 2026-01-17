{
  # Human-readable description of what this flake does (used for flake show and other tools)
  description = "NixForge - Secure Manager Node with k3s";

  # External dependencies (inputs) the flake uses - these are the sources that the flake depends on
  inputs = {
    # Main NixOS package set - using the unstable branch for latest features (this provides all packages and modules for NixOS)
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    # Disko - tool for declarative disk partitioning (allows defining disk layouts in Nix code)
    disko.url = "github:nix-community/disko";
    # Make sure disko uses the same nixpkgs version as we do (avoids version mismatches)
    disko.inputs.nixpkgs.follows = "nixpkgs";

    # sops-nix for secrets management (allows using sops for encrypted secrets in Nix configs)
    sops-nix.url = "github:Mic92/sops-nix";
    # Make sure sops-nix uses the same nixpkgs version as we do (avoids version mismatches)
    sops-nix.inputs.nixpkgs.follows = "nixpkgs";

    # nix-darwin for macOS builder (allows configuring macOS with Nix for local development and builders)
    darwin.url = "github:LnL7/nix-darwin";
    # Make sure darwin uses the same nixpkgs version as we do (avoids version mismatches)
    darwin.inputs.nixpkgs.follows = "nixpkgs";

    # Colmena for deployment (tool for deploying NixOS configs to remote machines)
    colmena.url = "github:zhaofengli/colmena";
    # Make sure colmena uses the same nixpkgs version as we do (avoids version mismatches)
    colmena.inputs.nixpkgs.follows = "nixpkgs";
  };

  # What this flake produces (outputs) - this defines what the flake builds or provides
  outputs = { self, nixpkgs, disko, sops-nix, darwin, colmena, ... }@inputs: let
    # Define the system architecture for Linux builds (used for cross-compilation from macOS)
    system = "x86_64-linux";

    # === SHARED CONFIGURATION ===
    # We define the modules list here so we can share it between the standard 'nixosConfigurations'
    # and the 'colmena' deployment configuration.
    managerModules = [
        # Include the disko module so we can use declarative disk config (enables disko.devices option)
        disko.nixosModules.disko
        # Include sops-nix for encrypted secrets (enables sops option)
        sops-nix.nixosModules.sops

        # Main configuration (anonymous module) - this is the core config block
        ({ config, pkgs, ... }: {
          # Enable modern nix features we need (enables flakes and new nix command syntax)
          nix.settings.experimental-features = [ "nix-command" "flakes" ];

          # Bootloader configuration for UEFI systems (uses systemd-boot for booting)
          boot.loader.systemd-boot.enable = true;
          # Allow modifying EFI variables (needed for bootloader setup)
          boot.loader.efi.canTouchEfiVariables = true;

          # === DISK LAYOUT (disko) - NO LUKS for first install ===
          disko.devices = {
            disk.main = {
              # Type of the device (here it's a disk)
              type = "disk";
              # Device path for the main disk (change if using the other NVMe)
              device = "/dev/nvme0n1";
              content = {
                # Partition table type (GPT for UEFI)
                type = "gpt";
                partitions = {
                  ESP = {
                    # EFI system partition type code
                    type = "EF00";
                    # Size of the boot partition
                    size = "512M";
                    content = {
                      # Content type (filesystem)
                      type = "filesystem";
                      # Filesystem format (vfat for EFI)
                      format = "vfat";
                      # Mount point for the boot partition
                      mountpoint = "/boot";
                    };
                  };
                  root = {
                    # Use remaining disk space for root
                    size = "100%";
                    content = {
                      # === CRITICAL FIX ===
                      # We changed this from "filesystem" to "btrfs".
                      # The generic "filesystem" type does not support subvolumes.
                      type = "btrfs";
                      
                      # Extra arguments for mkfs.btrfs (label the filesystem)
                      extraArgs = [ "-L" "nixos" ];
                      
                      # Subvolumes for btrfs (allows snapshotting individual parts)
                      subvolumes = {
                        "/" = {
                          # Mount point for root subvolume
                          mountpoint = "/";
                        };
                        "/nix" = {
                          # Mount point for nix store subvolume
                          mountpoint = "/nix";
                        };
                        "/persist" = {
                          # Mount point for persistent data subvolume
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
            # Hostname of the server
            hostName = "manager";
            # Static IP from InterServer
            interfaces.enp10s0f1np1.ipv4.addresses = [{
              # IP address
              address = "69.164.248.38";
              # Prefix length (subnet mask)
              prefixLength = 30;
            }];
            # Default gateway IP
            defaultGateway = "69.164.248.37";
            # DNS servers
            nameservers = [ "8.8.8.8" "1.1.1.1" ];
          };

          # Firewall: Allow only specific ports
          networking.firewall = {
            enable = true;
            allowedTCPPorts = [ 22 6443 80 443 ];  # SSH, k3s API, HTTP, HTTPS
          };

          # SSH hardening
          services.openssh = {
            enable = true;
            settings = {
              # Disable password authentication (use keys only)
              PasswordAuthentication = false;
              # Prohibit root login with password
              PermitRootLogin = "prohibit-password";
              # Disable keyboard-interactive authentication
              KbdInteractiveAuthentication = false;
            };
          };

          # SSH key for root
          users.users.root.openssh.authorizedKeys.keys = [
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE4qb5fQCQ5ZuyRyAKLD81yu12X2Mov0qePbpBwFwAaD"
          ]; 

          # Non-root user ruud
          users.users.ruud = {
            isNormalUser = true;
            # Groups for sudo and libvirt access
            extraGroups = [ "wheel" "libvirtd" "docker" ]; # Added docker for podman socket access
            openssh.authorizedKeys.keys = [
              "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE4qb5fQCQ5ZuyRyAKLD81yu12X2Mov0qePbpBwFwAaD"  # Same as root
            ];
          };

          # Sudo config
          security.sudo = {
            enable = true;
            # No password for wheel group
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
          # Set KUBECONFIG environment variable for kubectl access
          environment.variables = {
            KUBECONFIG = "/etc/rancher/k3s/k3s.yaml";
          };

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

  in {
    # NixOS configuration for the manager server (this is the main config for your Linux server)
    nixosConfigurations.manager = nixpkgs.lib.nixosSystem {
      # Target architecture (standard 64-bit Intel/AMD) for the server config
      system = system;
      # Use the shared modules defined above
      modules = managerModules;
    };

    # macOS builder configuration
    darwinConfigurations.builder = darwin.lib.darwinSystem {
      system = "aarch64-darwin";
      modules = [ 
        # Inline minimal darwin config
        ({ pkgs, ... }: {
           nix.settings.experimental-features = [ "nix-command" "flakes" ];
           services.nix-daemon.enable = true;
           system.stateVersion = 6;
        })
      ];
    };

    # Colmena deployment hive - Colmena reads this attribute directly
    colmena = {
      meta = {
        nixpkgs = import nixpkgs { system = "x86_64-linux"; };
        specialArgs = { inherit inputs; };
      };

      defaults = { 
        deployment.targetUser = "root"; 
        
        # CRITICAL: Build on the target server (Linux) instead of the local machine (macOS)
        # to avoid cross-compilation complexity.
        deployment.buildOnTarget = true;
      };

      manager = {
        deployment.targetHost = "69.164.248.38";
        imports = managerModules;  # Use the shared module list
      };
    };
  };
}