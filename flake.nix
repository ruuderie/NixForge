{
  # Human-readable description of what this flake does (used for flake show and other tools)
  description = "NixForge - Secure Manager Node with k3s + Data Services";

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
          
          # Allow unfree packages (Required for non-Apache TimescaleDB or specific monitoring tools)
          nixpkgs.config.allowUnfree = true;

          # Bootloader configuration for UEFI systems (uses systemd-boot for booting)
          boot.loader.systemd-boot.enable = true;
          # Allow modifying EFI variables (needed for bootloader setup)
          boot.loader.efi.canTouchEfiVariables = true;

          # === DISK LAYOUT (disko) ===
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
                      # Filesystem type is BTRFS to support subvolumes
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
            # Static IP from InterServer configuration
            interfaces.enp10s0f1np1.ipv4.addresses = [{
              # IP address of the server
              address = "69.164.248.38";
              # Prefix length (subnet mask)
              prefixLength = 30;
            }];
            # Default gateway IP for routing traffic out
            defaultGateway = "69.164.248.37";
            # DNS servers (Google and Cloudflare)
            nameservers = [ "8.8.8.8" "1.1.1.1" ];
            
            # Firewall: Allow only specific ports
            firewall = {
              # Enable the firewall service
              enable = true;
              # List of allowed TCP ports
              # Added 5432 (Postgres) and 3000 (Grafana)
              allowedTCPPorts = [ 22 6443 80 443 5432 3000 ];  # SSH, k3s API, HTTP, HTTPS, DB, Dashboard
            };
          };

          # === DATABASE CONFIGURATION (Super-Postgres) ===
          services.postgresql = {
            enable = true;
            package = pkgs.postgresql_16;
            
            # Enable extensions for RAG, Geo, and TimeSeries
            extensions = ps: with ps; [
              postgis         # Geospatial
              pgvector        # Vector Search / RAG
              timescaledb     # Time-series / Financial
            ];

            # Declarative User Management
            # FIX: Changed "ruud_db" to "ruud" to match ensureDBOwnership requirement
            ensureDatabases = [ "ruud" "postgres" "oply_property_group" "oply_finance" "oply_logistics" "oply_intelligence" ];
            ensureUsers = [
              {
                name = "ruud";
                ensureDBOwnership = true;
              }
            ];

            # Performance Tuning for NVMe/32GB RAM
            settings = {
              shared_buffers = "4GB";      # Approx 25% of RAM
              work_mem = "16MB";           # Memory per operation
              max_connections = "300";
              effective_cache_size = "12GB";
              maintenance_work_mem = "1GB";
              
              # Enable TimescaleDB preloader
              shared_preload_libraries = "timescaledb,pg_stat_statements";
              
              # Listening on all interfaces (security handled by pg_hba.conf)
              # FIX: Use mkForce to override NixOS default of "localhost"
              listen_addresses = pkgs.lib.mkForce "*"; 
            };

            # Authentication (pg_hba.conf)
            # 1. Allow root/postgres user via socket (local trust)
            # 2. Allow remote users ONLY via SCRAM-SHA-256 password
            # 3. Allow k3s pods (10.42.0.0/16) via password
            authentication = pkgs.lib.mkOverride 10 ''
              # TYPE  DATABASE        USER            ADDRESS                 METHOD
              local   all             all                                     trust
              host    all             all             127.0.0.1/32            scram-sha-256
              host    all             all             10.42.0.0/16            scram-sha-256
              host    all             all             ::1/128                 trust
              host    all             all             0.0.0.0/0               scram-sha-256
            '';
          };

          # === OBSERVABILITY STACK ===
          
          # 1. Node Exporter (Hardware Metrics)
          services.prometheus.exporters.node = {
            enable = true;
            enabledCollectors = [ "systemd" ];
          };

          # 2. Postgres Exporter (Database Metrics)
          services.prometheus.exporters.postgres = {
            enable = true;
            runAsLocalSuperUser = true;
          };

          # 3. Prometheus (The Collector)
          services.prometheus = {
            enable = true;
            port = 9090;
            scrapeConfigs = [
              {
                job_name = "node";
                static_configs = [{ targets = [ "127.0.0.1:9100" ]; }];
              }
              {
                job_name = "postgres";
                static_configs = [{ targets = [ "127.0.0.1:9187" ]; }];
              }
            ];
          };

          # 4. Grafana (The Dashboard)
          services.grafana = {
            enable = true;
            settings = {
              server = {
                # Accessible on http://69.164.248.38:3000
                http_addr = "0.0.0.0";
                http_port = 3000;
              };
            };
            # Auto-connect Prometheus data source
            provision.datasources.settings.datasources = [{
              name = "Prometheus";
              type = "prometheus";
              access = "proxy";
              url = "http://127.0.0.1:9090";
            }];
          };

          # SSH hardening configuration
          services.openssh = {
            # Enable the SSH daemon
            enable = true;
            settings = {
              # Disable password authentication (use keys only for security)
              PasswordAuthentication = false;
              # Prohibit root login with password (keys still allowed if configured)
              PermitRootLogin = "prohibit-password";
              # Disable keyboard-interactive authentication (prevents PAM prompting)
              KbdInteractiveAuthentication = false;
            };
          };

          # SSH key for root user access
          users.users.root.openssh.authorizedKeys.keys = [
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE4qb5fQCQ5ZuyRyAKLD81yu12X2Mov0qePbpBwFwAaD"
          ]; 

          # Configuration for non-root user 'ruud'
          users.users.ruud = {
            # This is a regular user account
            isNormalUser = true;
            # Groups for sudo (wheel), libvirt access, and container management
            extraGroups = [ "wheel" "libvirtd" "docker" ]; 
            # SSH keys for this user
            openssh.authorizedKeys.keys = [
              "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE4qb5fQCQ5ZuyRyAKLD81yu12X2Mov0qePbpBwFwAaD"
            ];
          };

          # Sudo configuration
          security.sudo = {
            # Enable sudo
            enable = true;
            # Allow members of 'wheel' group to sudo without typing a password
            wheelNeedsPassword = false;
          };

          # sops secrets configuration
          sops = {
            # Path to the age key used for decryption
            age.keyFile = "/var/lib/sops-nix/key.txt";
            # Path to the encrypted secrets file
            defaultSopsFile = ./secrets/secrets.yaml;
          };

          # === k3s Kubernetes Configuration ===
          services.k3s = {
            # Enable the k3s service
            enable = true;
            # Role of this node (server = control plane)
            role = "server";
            # Initialize a new cluster (required for the first node)
            clusterInit = true;
            # Extra flags: disable traefik (we use custom ingress) and enable API auditing
            extraFlags = "--disable=traefik --kube-apiserver-arg=audit-log-path=/var/log/k3s/audit.log";
          };

          # Virtualization (libvirt) configuration
          virtualisation.libvirtd.enable = true;
          # Enable virt-manager UI support
          programs.virt-manager.enable = true;
          # Add root to libvirtd group to manage VMs
          users.users.root.extraGroups = [ "libvirtd" ];

          # Podman (Docker alternative) configuration
          virtualisation.podman = {
            # Enable Podman
            enable = true;
            # Create a Docker socket so Docker commands work with Podman
            dockerCompat = true;
            # Enable DNS in the default Podman network
            defaultNetwork.settings.dns_enabled = true;
          };

          # System Packages installed globally
          environment.systemPackages = with pkgs; [
            kubectl      # CLI for Kubernetes
            k9s          # Terminal UI for Kubernetes management
            helm         # Kubernetes package manager
            curl         # CLI for data transfer
            git          # Version control
            fail2ban     # Intrusion prevention framework
            bandwhich    # Bandwidth utilization monitor
            restic       # Backup program
            podman-compose # Compose implementation for Podman
          ];

          # Environment variables
          environment.variables = {
            # Tell kubectl where to find the k3s configuration
            KUBECONFIG = "/etc/rancher/k3s/k3s.yaml";
          };

          # Fail2ban service configuration
          services.fail2ban.enable = true;

          # System auto-upgrade configuration
          system.autoUpgrade = {
            # Enable automatic upgrades
            enable = true;
            # Do not reboot automatically (safer for servers)
            allowReboot = false;
          };

          # Kernel sysctl tuning
          boot.kernel.sysctl = {
            # Disable unprivileged BPF (security hardening)
            "kernel.unprivileged_bpf_disabled" = 1;
            # Disable BPF JIT hardening (often required for some tools, set to 0 to disable JIT hardening)
            "net.core.bpf_jit_enable" = 0;
          };

          # NixOS state version (do not change this unless you know what you are doing)
          system.stateVersion = "25.05";
        })
    ];

  in {
    # 1. Standard NixOS Config (optional, but good for validation via nixos-rebuild)
    nixosConfigurations.manager = nixpkgs.lib.nixosSystem {
      # Target system architecture
      system = system;
      # Modules to include in the system
      modules = managerModules;
    };

    # 2. macOS Builder Config (Your local environment for 'darwin-rebuild')
    darwinConfigurations.builder = darwin.lib.darwinSystem {
      # Target system architecture for the Mac
      system = "aarch64-darwin";
      modules = [ 
        # Inline minimal darwin config
        ({ pkgs, ... }: {
           # Enable experimental features for the Mac builder
           nix.settings.experimental-features = [ "nix-command" "flakes" ];
           # Enable the Nix daemon
           services.nix-daemon.enable = true;
           # Darwin state version
           system.stateVersion = 6;
        })
      ];
    };

    # 3. Colmena Configuration (The Fix)
    colmena = {
      meta = {
        # Pins nixpkgs to the input version for all nodes in the hive
        nixpkgs = import nixpkgs {
          system = "x86_64-linux";
        };
        # Pass flake inputs to modules (allows accessing self, inputs, etc.)
        specialArgs = { inherit inputs; };
      };

      defaults = { 
        # Default user to SSH into for deployment
        deployment.targetUser = "root"; 
        
        # CRITICAL: Build on the target server (Linux) instead of the local machine (macOS)
        # to avoid cross-compilation complexity and errors.
        deployment.buildOnTarget = true;
      };

      # Node definition for 'manager'
      manager = {
        # The IP address of the target server
        deployment.targetHost = "69.164.248.38";
        # Import the shared configuration modules
        imports = managerModules;
      };
    };

    # 4. COMPATIBILITY BRIDGE (The Fix for 'schema' errors)
    # This creates the exact "Hive" object your local tool is expecting.
    # It bridges the gap between the new configuration format and the old tool.
    colmenaHive = colmena.lib.makeHive self.outputs.colmena;
  };
}