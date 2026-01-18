{
  # =======================================================================================
  # NIXFORGE - INFRASTRUCTURE AS CODE (IaC) DEFINITION
  # =======================================================================================
  # Description: Defines the declarative configuration for the 'Manager' node.
  # Role: Hybrid K3s Control Plane + High-Performance Database Host + Observability Hub.
  description = "NixForge - Secure Manager Node with k3s + Data Services";

  # =======================================================================================
  # 1. INPUTS (DEPENDENCIES)
  # Sources for all software and modules used in this configuration.
  # =======================================================================================
  inputs = {
    # Main NixOS package set. 
    # We use 'unstable' to get the absolute latest kernel, Postgres 16, and k3s versions.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    # Disko: Provides declarative disk partitioning.
    # Allows us to format and partition the NVMe drive via Nix code, not manual scripts.
    disko.url = "github:nix-community/disko";
    # Force disko to use our version of nixpkgs to avoid dependency conflicts.
    disko.inputs.nixpkgs.follows = "nixpkgs";

    # Sops-Nix: Secrets management integration (Mozilla SOPS).
    # Decrypts secrets (API keys, passwords) at runtime using the server's SSH key.
    sops-nix.url = "github:Mic92/sops-nix";
    # Force sops-nix to use our version of nixpkgs.
    sops-nix.inputs.nixpkgs.follows = "nixpkgs";

    # Nix-Darwin: Allows managing the macOS build environment (your local laptop).
    # Useful if you want to enforce specific developer tooling on your Mac.
    darwin.url = "github:LnL7/nix-darwin";
    # Force darwin to use our version of nixpkgs.
    darwin.inputs.nixpkgs.follows = "nixpkgs";

    # Colmena: The deployment tool. 
    # Replaces 'nixos-rebuild' for remote deployments, offering parallel builds and better logs.
    colmena.url = "github:zhaofengli/colmena";
    # Force colmena to use our version of nixpkgs.
    colmena.inputs.nixpkgs.follows = "nixpkgs";
  };

  # =======================================================================================
  # 2. OUTPUTS (BUILD TARGETS)
  # Defines the resulting system configurations for Linux (Server) and Darwin (Local).
  # =======================================================================================
  outputs = { self, nixpkgs, disko, sops-nix, darwin, colmena, ... }@inputs: let
    # Target Architecture: The server is a standard Intel/AMD 64-bit machine.
    system = "x86_64-linux";

    # --- HELPER: ENVIRONMENT VARIABLE LOADER ---
    # Rationale: Nix's built-in `getEnv` returns an empty string if a var is missing.
    # This helper checks for empty strings and provides a safe default.
    getEnv = name: default:
      let val = builtins.getEnv name;
      in if val != "" then val else default;

    # --- CONFIGURATION: NETWORK PARAMETERS ---
    # Rationale: Abstracting these values here makes the config portable.
    # We use the 'getEnv' helper to allow overriding these via CLI if needed later.
    serverConfig = {
      # Fallback to a dummy IP to prevent accidental leakage in public code
      ip = getEnv "SERVER_IP" "127.0.0.1";
      gateway = getEnv "SERVER_GATEWAY" "127.0.0.1"; 
      interface = getEnv "SERVER_INTERFACE" "enp10s0f1np1"; # Interface names are generally safe to publish
    };

    # ===================================================================================
    # 3. MANAGER MODULES (SHARED CONFIGURATION)
    # These modules define the actual system state. Defined here as a list so they can be
    # shared between standard 'nixosConfigurations' and 'colmena' deployment targets.
    # ===================================================================================
    managerModules = [
        # Import the Disko module to enable the 'disko.devices' options
        disko.nixosModules.disko
        # Import the Sops module to enable the 'sops' options
        sops-nix.nixosModules.sops

        # --- CORE SYSTEM CONFIGURATION (Anonymous Module) ---
        ({ config, pkgs, ... }: {
          # Nix Settings: Enable 'flakes' (modern project structure) and 'nix-command' (modern CLI).
          nix.settings.experimental-features = [ "nix-command" "flakes" ];
          
          # Licensing: Allow unfree packages. 
          # Required for TimescaleDB (TSL license), hardware drivers, and some monitoring tools.
          nixpkgs.config.allowUnfree = true;

          # Bootloader: Use systemd-boot.
          # It is simpler and faster than GRUB for modern UEFI systems.
          boot.loader.systemd-boot.enable = true;
          # EFI: Allow NixOS to update boot variables in the motherboard NVRAM.
          boot.loader.efi.canTouchEfiVariables = true;

          # --- STORAGE ARCHITECTURE (NVMe) ---
          # Rationale: Declarative partitioning ensures the disk layout matches the code.
          # We use BTRFS for its snapshot capabilities (rollback) and subvolume management.
          disko.devices = {
            disk.main = {
              type = "disk";
              device = "/dev/nvme0n1"; # Primary NVMe drive
              content = {
                type = "gpt"; # GUID Partition Table (Required for UEFI booting)
                partitions = {
                  ESP = {
                    type = "EF00"; # EFI System Partition Type Code
                    size = "512M"; # Standard size for boot loaders
                    content = { 
                      type = "filesystem"; 
                      format = "vfat"; # UEFI requires VFAT/FAT32
                      mountpoint = "/boot"; 
                    };
                  };
                  root = {
                    size = "100%"; # Use all remaining disk space
                    content = {
                      type = "btrfs"; # Filesystem: BTRFS
                      extraArgs = [ "-L" "nixos" ]; # Label the filesystem "nixos"
                      subvolumes = {
                        "/" = { mountpoint = "/"; };           # System Root (Ephemeral-ish)
                        "/nix" = { mountpoint = "/nix"; };     # Nix Store (Heavy write, reproducible)
                        "/persist" = { mountpoint = "/persist"; }; # Persistent Data (Databases, etc.)
                      };
                    };
                  };
                };
              };
            };
          };

          # --- NETWORK CONFIGURATION ---
          networking = {
            hostName = "manager"; # The internal hostname of the server
            # Static IP Configuration:
            # Critical for a server to ensure consistent reachability and DNS mapping.
            interfaces.${serverConfig.interface}.ipv4.addresses = [{
              address = serverConfig.ip;
              prefixLength = 30; # Subnet mask (provider specific)
            }];
            defaultGateway = serverConfig.gateway; # Routing gateway
            nameservers = [ "8.8.8.8" "1.1.1.1" ]; # Upstream DNS (Google/Cloudflare)
            
            # Security: Firewall Configuration
            firewall = {
              enable = true;
              # Allow only strictly necessary ingress ports. All others are dropped.
              allowedTCPPorts = [ 
                22    # SSH (Remote Access)
                6443  # Kubernetes API (Cluster Management)
                80    # HTTP (Web Traffic)
                443   # HTTPS (Secure Web Traffic)
                5432  # PostgreSQL (Database Access from K8s)
                3000  # Grafana (Observability Dashboard)
              ];
            };
          };

          # --- DATABASE LAYER: POSTGRESQL (Hybrid Stack) ---
          services.postgresql = {
            enable = true;
            package = pkgs.postgresql_16; # Use latest stable Major version (16)
            
            # Extensions: Load these libraries into the Postgres runtime.
            extensions = ps: with ps; [
              postgis         # Geospatial engine (Maps, Routes)
              pgvector        # Vector embeddings (AI/RAG memory)
              timescaledb     # Time-series optimization (Finance/Ticks)
            ];

            # Declarative Database Provisioning
            # Ensures these specific databases exist on startup.
            ensureDatabases = [ 
              "ruud"                 # Default user database
              "postgres"             # System database (required by tools)
              "oply_property_group"  # Real Estate Data Isolation
              "oply_finance"         # Financial/Crypto Data Isolation
              "oply_logistics"       # Logistics/Geo Data Isolation
              "oply_intelligence"    # AI/RAG Data Isolation
            ];
            
            # Declarative User Provisioning
            # Ensures user 'ruud' exists and owns their DB.
            ensureUsers = [
              {
                name = "ruud";
                ensureDBOwnership = true; # Grants 'ALL PRIVILEGES' on db 'ruud' to user 'ruud'
              }
            ];

            # Performance Tuning: Optimized for ~32GB RAM / NVMe Storage
            settings = {
              shared_buffers = "4GB";      # Cache memory (~25% of RAM)
              work_mem = "16MB";           # Memory per sort/hash operation
              max_connections = "300";     # Concurrency limit (Keep moderate for K8s)
              effective_cache_size = "12GB"; # OS Cache estimate (~75% of RAM)
              maintenance_work_mem = "1GB"; # Speed up vacuums and index builds
              
              # Preload Libraries: Required for TimescaleDB and Monitoring hooks
              shared_preload_libraries = "timescaledb,pg_stat_statements";
              
              # Listening Address:
              # By default, NixOS locks this to 'localhost'.
              # We use mkForce to override it to '*', allowing connections from K3s pods.
              # Security is handled by the authentication block below.
              listen_addresses = pkgs.lib.mkForce "*"; 
            };

            # Authentication (pg_hba.conf) Rules
            # Security Policy:
            # 1. Localhost (Socket) -> Trust (Peer auth, safe for system users)
            # 2. Network (Remote/K8s) -> SCRAM-SHA-256 (Strict Password, no cleartext)
            authentication = pkgs.lib.mkOverride 10 ''
              # TYPE  DATABASE        USER            ADDRESS                 METHOD
              local   all             all                                     trust
              host    all             all             127.0.0.1/32            scram-sha-256
              host    all             all             10.42.0.0/16            scram-sha-256
              host    all             all             ::1/128                 trust
              host    all             all             0.0.0.0/0               scram-sha-256
            '';
          };

          # --- OBSERVABILITY STACK (Prometheus + Grafana) ---
          
          # 1. Hardware Metrics: Exports CPU, RAM, Disk, Net stats to port 9100
          services.prometheus.exporters.node = {
            enable = true;
            enabledCollectors = [ "systemd" ]; # Also collect Systemd service states
          };

          # 2. Database Metrics: Exports query perf, locks, cache hit rates to port 9187
          services.prometheus.exporters.postgres = {
            enable = true;
            runAsLocalSuperUser = true; # Allows exporter to see internal DB stats via socket
          };

          # 3. Prometheus: The time-series database that pulls metrics from exporters
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

          # 4. Grafana: The Visualization UI
          services.grafana = {
            enable = true;
            settings = {
              server = {
                # Bind to all interfaces so we can access via Public IP
                http_addr = "0.0.0.0";
                http_port = 3000;
              };
            };
            # Auto-Provisioning: Automatically connect Prometheus as a datasource on startup
            provision.datasources.settings.datasources = [{
              name = "Prometheus";
              type = "prometheus";
              access = "proxy";
              url = "http://127.0.0.1:9090";
            }];
          };

          # --- SECURITY: ACCESS CONTROL (SSH) ---
          services.openssh = {
            enable = true;
            settings = {
              PasswordAuthentication = false;      # Disable password login (Key only)
              PermitRootLogin = "prohibit-password"; # Allow root only via Key
              KbdInteractiveAuthentication = false; # Disable challenge-response
            };
          };

          # Root Access:
          # Using cleartext public key is SAFE and standard practice.
          # The private key remains on your local machine.
          users.users.root.openssh.authorizedKeys.keys = [
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE4qb5fQCQ5ZuyRyAKLD81yu12X2Mov0qePbpBwFwAaD"
          ]; 

          # User 'ruud' Access (Normal User):
          users.users.ruud = {
            isNormalUser = true;
            extraGroups = [ "wheel" "libvirtd" "docker" ]; # Admin groups + Virtualization
            openssh.authorizedKeys.keys = [
              "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE4qb5fQCQ5ZuyRyAKLD81yu12X2Mov0qePbpBwFwAaD"
            ];
          };

          # Sudo Configuration
          security.sudo = {
            enable = true;
            wheelNeedsPassword = false; # Passwordless sudo for admins (convenience)
          };

          # --- SECRETS MANAGEMENT (SOPS) ---
          # Decrypts ./secrets/secrets.yaml at runtime using the host key.
          sops = {
            age.keyFile = "/var/lib/sops-nix/key.txt";
            defaultSopsFile = ./secrets/secrets.yaml;
          };

          # --- CONTAINER ORCHESTRATION (K3S) ---
          services.k3s = {
            enable = true;
            role = "server"; # Acts as Control Plane + Worker
            clusterInit = true; # Initialize new cluster (use once)
            # Disable Traefik: We will manage Ingress manually or via other tools later.
            # Enable API Auditing: Logs all API requests for security auditing.
            extraFlags = "--disable=traefik --kube-apiserver-arg=audit-log-path=/var/log/k3s/audit.log";
          };

          # --- VIRTUALIZATION LAYER ---
          virtualisation.libvirtd.enable = true; # KVM/QEMU backend daemon
          programs.virt-manager.enable = true;   # UI Management tool (X11 forwarding or local)
          users.users.root.extraGroups = [ "libvirtd" ];

          # Podman: Daemonless container engine (Docker alternative)
          virtualisation.podman = {
            enable = true;
            dockerCompat = true; # Alias 'docker' commands to 'podman'
            defaultNetwork.settings.dns_enabled = true; # Allow containers to resolve names
          };

          # --- SYSTEM PACKAGES ---
          # These tools are installed into the global System Profile ($PATH)
          environment.systemPackages = with pkgs; [
            kubectl      # K8s CLI
            k9s          # K8s Terminal UI
            helm         # K8s Package Manager
            curl         # Network tool
            git          # Version Control
            fail2ban     # Intrusion Prevention
            bandwhich    # Bandwidth Monitor
            restic       # Backup Tool
            podman-compose # Podman Compose
          ];

          # Environment Variables: 
          # Point kubectl to the correct config file by default so root can run commands immediately.
          environment.variables = {
            KUBECONFIG = "/etc/rancher/k3s/k3s.yaml";
          };

          # --- SECURITY SERVICES ---
          # Fail2Ban: Scans logs and bans IPs that show malicious signs (e.g. SSH brute force).
          services.fail2ban.enable = true; 

          # --- MAINTENANCE ---
          # Auto-Upgrade: Keeps the system Nix channels up to date.
          system.autoUpgrade = {
            enable = true;
            allowReboot = false; # Never reboot automatically (Risk of downtime during critical tasks)
          };

          # --- KERNEL TUNING ---
          boot.kernel.sysctl = {
            "kernel.unprivileged_bpf_disabled" = 1; # Harden BPF to prevent privilege escalation
            "net.core.bpf_jit_enable" = 0;          # Disable JIT to prevent JIT spraying attacks
          };

          # NixOS Version Lock (Do not change unless you know why)
          # Defines the state version for stateful data migration logic.
          system.stateVersion = "25.05";
        })
    ];

  in {
    # 1. Standard NixOS Config (Useful for 'nixos-rebuild build' checks or VM testing)
    nixosConfigurations.manager = nixpkgs.lib.nixosSystem {
      system = system;
      modules = managerModules;
    };

    # 2. macOS Builder Config (Your local environment)
    # Minimal config to allow 'darwin-rebuild' to function.
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

    # 3. Colmena Configuration (Modern Deployment)
    # This block defines the 'Hive' used by Colmena to deploy to the server.
    colmena = {
      meta = {
        nixpkgs = import nixpkgs { system = "x86_64-linux"; };
        specialArgs = { inherit inputs; };
      };

      defaults = { 
        deployment.targetUser = "root"; # Login as root
        
        # CRITICAL: Build on the target server.
        # This bypasses the need for a Linux cross-compiler on your Mac.
        # The derivation is evaluated locally, sent to the server, built there, and activated.
        deployment.buildOnTarget = true;
      };

      manager = {
        deployment.targetHost = serverConfig.ip; # Where to deploy
        imports = managerModules; # What to deploy
      };
    };

    # 4. COMPATIBILITY BRIDGE
    # Generates the legacy 'Hive' object structure for older Colmena CLI versions.
    # Required to prevent "schema version" errors.
    colmenaHive = colmena.lib.makeHive self.outputs.colmena;
  };
}