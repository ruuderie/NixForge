{
  # Human-readable description of what this flake does (used for flake show and other tools)
  description = "NixForge - Secure Manager Node with k3s";

  # External dependencies (inputs) the flake uses
  inputs = {
    # Main NixOS package set - using the unstable branch for latest features
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    # Disko - tool for declarative disk partitioning
    disko.url = "github:nix-community/disko";
    disko.inputs.nixpkgs.follows = "nixpkgs";

    # sops-nix for secrets management
    sops-nix.url = "github:Mic92/sops-nix";
    sops-nix.inputs.nixpkgs.follows = "nixpkgs";

    # nix-darwin for macOS builder (allows configuring macOS for local dev)
    darwin.url = "github:LnL7/nix-darwin";
    darwin.inputs.nixpkgs.follows = "nixpkgs";

    # Colmena for deployment
    colmena.url = "github:zhaofengli/colmena";
    colmena.inputs.nixpkgs.follows = "nixpkgs";
  };

  # What this flake produces (outputs)
  outputs = { self, nixpkgs, disko, sops-nix, darwin, colmena, ... }@inputs: let
    # Define the system architecture for Linux builds
    system = "x86_64-linux";

    # === SHARED CONFIGURATION ===
    # Defined here so it can be shared between 'nixosConfigurations' and 'colmena'
    managerModules = [
        # Include the disko module
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

          # === DISK LAYOUT (disko) ===
          disko.devices = {
            disk.main = {
              type = "disk";
              device = "/dev/nvme0n1";
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
                      type = "btrfs";
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

          # Basic network config
          networking = {
            hostName = "manager";
            interfaces.enp10s0f1np1.ipv4.addresses = [{
              address = "69.164.248.38";
              prefixLength = 30;
            }];
            defaultGateway = "69.164.248.37";
            nameservers = [ "8.8.8.8" "1.1.1.1" ];
            
            # Firewall: Allow only specific ports
            firewall = {
              enable = true;
              allowedTCPPorts = [ 22 6443 80 443 ];  # SSH, k3s API, HTTP, HTTPS
            };
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

          # SSH keys
          users.users.root.openssh.authorizedKeys.keys = [
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE4qb5fQCQ5ZuyRyAKLD81yu12X2Mov0qePbpBwFwAaD"
          ]; 

          users.users.ruud = {
            isNormalUser = true;
            extraGroups = [ "wheel" "libvirtd" "docker" ]; 
            openssh.authorizedKeys.keys = [
              "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE4qb5fQCQ5ZuyRyAKLD81yu12X2Mov0qePbpBwFwAaD"
            ];
          };

          security.sudo = {
            enable = true;
            wheelNeedsPassword = false;
          };

          # sops secrets
          sops = {
            age.keyFile = "/var/lib/sops-nix/key.txt";
            defaultSopsFile = ./secrets/secrets.yaml;
          };

          # === k3s Kubernetes ===
          services.k3s = {
            enable = true;
            role = "server";
            clusterInit = true;
            extraFlags = "--disable=traefik --kube-apiserver-arg=audit-log-path=/var/log/k3s/audit.log";
          };

          # Virtualization
          virtualisation.libvirtd.enable = true;
          programs.virt-manager.enable = true;
          users.users.root.extraGroups = [ "libvirtd" ];

          virtualisation.podman = {
            enable = true;
            dockerCompat = true;
            defaultNetwork.settings.dns_enabled = true;
          };

          # System Packages
          environment.systemPackages = with pkgs; [
            kubectl
            k9s
            helm
            curl
            git
            fail2ban
            bandwhich
            restic
            podman-compose
          ];

          environment.variables = {
            KUBECONFIG = "/etc/rancher/k3s/k3s.yaml";
          };

          services.fail2ban.enable = true;

          system.autoUpgrade = {
            enable = true;
            allowReboot = false;
          };

          boot.kernel.sysctl = {
            "kernel.unprivileged_bpf_disabled" = 1;
            "net.core.bpf_jit_enable" = 0;
          };

          system.stateVersion = "25.05";
        })
    ];

  in {
    # 1. Standard NixOS Config (optional, but good for validation)
    nixosConfigurations.manager = nixpkgs.lib.nixosSystem {
      system = system;
      modules = managerModules;
    };

    # 2. macOS Builder Config (Your local environment)
    darwinConfigurations.builder = darwin.lib.darwinSystem {
      system = "aarch64-darwin";
      modules = [ 
        ({ pkgs, ... }: {
           nix.settings.experimental-features = [ "nix-command" "flakes" ];
           services.nix-daemon.enable = true;
           system.stateVersion = 6;
        })
      ];
    };

    # 3. Colmena Configuration (The Fix)
    colmena = {
      meta = {
        # Pins nixpkgs to the input version
        nixpkgs = import nixpkgs {
          system = "x86_64-linux";
        };
        # Pass inputs if needed
        specialArgs = { inherit inputs; };
      };

      defaults = { 
        deployment.targetUser = "root"; 
        # CRITICAL: Build on the target server to avoid macOS cross-compilation issues
        deployment.buildOnTarget = true;
      };

      manager = {
        deployment.targetHost = "69.164.248.38";
        imports = managerModules;
      };
    };
  };
}