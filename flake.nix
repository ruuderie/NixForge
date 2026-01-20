{
  # =======================================================================================
  # NIXFORGE - INFRASTRUCTURE AS CODE (IaC) DEFINITION
  # =======================================================================================
  # Description: Defines the declarative configuration for the 'Manager' node.
  # Role: Hybrid K3s Control Plane + High-Performance Database Host + Observability Hub.
  # Security Level: High (Secrets Encrypted, IPs Gitignored, SSH Hardened).
  description = "NixForge - Secure Manager Node with k3s + Data Services";

  # =======================================================================================
  # 1. INPUTS (DEPENDENCIES)
  # Sources for all software and modules used in this configuration.
  # =======================================================================================
  inputs = {
    # NixOS Main Repository: Using 'unstable' for access to the latest kernel and software versions.
    # Architecture: We track unstable to get Postgres 16, latest K3s, and newest monitoring tools.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    # Disko: Provides declarative disk partitioning.
    # Architecture: We use code to define partitions (GPT/BTRFS) to ensure the server setup is reproducible 
    # and not dependent on manual commands run during the initial install.
    disko.url = "github:nix-community/disko";
    disko.inputs.nixpkgs.follows = "nixpkgs"; # Enforce version alignment to prevent dependency hell.

    # Sops-Nix: Secrets management integration (Mozilla SOPS).
    # Architecture: This decouples secrets from the codebase. Secrets are encrypted in git
    # and decrypted only in RAM on the server using its private SSH key.
    sops-nix.url = "github:Mic92/sops-nix";
    sops-nix.inputs.nixpkgs.follows = "nixpkgs"; # Enforce version alignment.

    # Nix-Darwin: Allows managing the macOS build environment (your local laptop).
    # Architecture: Ensures your local toolchain (colmena, sops) matches the server's version.
    darwin.url = "github:LnL7/nix-darwin";
    darwin.inputs.nixpkgs.follows = "nixpkgs"; # Enforce version alignment.

    # Colmena: The deployment tool.
    # Architecture: Replaces 'nixos-rebuild' for remote deployments. It offers parallel builds,
    # better error reporting, and distinct evaluation/build phases for stability.
    colmena.url = "github:zhaofengli/colmena";
    colmena.inputs.nixpkgs.follows = "nixpkgs"; # Enforce version alignment.
  };

  # =======================================================================================
  # 2. OUTPUTS (BUILD TARGETS)
  # Defines the resulting system configurations for Linux (Server) and Darwin (Local).
  # =======================================================================================
  outputs = { self, nixpkgs, disko, sops-nix, darwin, colmena, ... }@inputs: let
    # Architecture: Target the standard x86_64 linux kernel for the server.
    system = "x86_64-linux";

    # === ARCHITECTURAL PATTERN: GITIGNORED CONFIGURATION ===
    # Rationale: We separate "Code" (Public) from "State" (Private IPs).
    # This allows the repo to be public on GitHub without leaking the server's location.
    configPath = ./local-config.nix;
    
    # Logic: Try to import the private file. If missing, fail with a helpful error.
    # This prevents 'localhost' connection errors by enforcing the existence of configuration.
    serverConfig = if builtins.pathExists configPath 
      then import configPath 
      else throw ''
        CRITICAL ARCHITECTURE ERROR: 'local-config.nix' is missing!
        
        To deploy this flake safely, you must create 'local-config.nix' in the root directory
        and add it to .gitignore. It should contain your private infrastructure details:
        
        {
          serverIP = "YOUR_IP";
          serverGateway = "YOUR_GATEWAY";
          serverInterface = "enp10s0f1np1";
        }
      '';

    # ===================================================================================
    # 3. MANAGER MODULES (SHARED CONFIGURATION)
    # These modules define the actual system state. Defined here as a list so they can be
    # shared between standard 'nixosConfigurations' and 'colmena' deployment targets.
    # ===================================================================================
    managerModules = [
        # Import the Disko module to enable the 'disko.devices' options for storage.
        disko.nixosModules.disko
        # Import the Sops module to enable the 'sops' options for secrets.
        sops-nix.nixosModules.sops

        # --- CORE SYSTEM CONFIGURATION (Anonymous Module) ---
        ({ config, pkgs, ... }: {
          # Nix Settings: Enable 'flakes' (modern project structure) and 'nix-command' (modern CLI).
          nix.settings.experimental-features = [ "nix-command" "flakes" ];
          
          # Licensing: Allow unfree packages. 
          # Rationale: Required for TimescaleDB (TSL license), hardware drivers, and some monitoring tools.
          nixpkgs.config.allowUnfree = true;

          # Bootloader: Use systemd-boot.
          # Architecture: Simpler and faster than GRUB for UEFI systems. No legacy MBR support needed.
          boot.loader.systemd-boot.enable = true;
          # EFI: Allow NixOS to update boot variables in the motherboard NVRAM.
          boot.loader.efi.canTouchEfiVariables = true;

          # --- STORAGE ARCHITECTURE (NVMe) ---
          # Architecture: Declarative partitioning ensures the disk layout matches the code.
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
            # Architecture: Critical for a server to ensure consistent reachability and DNS mapping.
            # We load the actual values from the gitignored 'local-config.nix'.
            interfaces.${serverConfig.serverInterface}.ipv4.addresses = [{
              address = serverConfig.serverIP;
              prefixLength = 30; # Subnet mask (provider specific)
            }];
            defaultGateway = serverConfig.serverGateway; # Routing gateway
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
                # Note: Ports 9090 (Prometheus) and 3100 (Loki) are purposefully NOT exposed.
                # They are accessed internally by Grafana via localhost.
              ];
            };
          };

          # --- DATABASE LAYER: POSTGRESQL (Hybrid Stack) ---
          # Architecture: Running DB on bare metal (not inside K8s) provides max NVMe performance
          # and simplifies backup/restore of massive datasets.
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
            # Architecture: Ensure these databases exist on startup.
            ensureDatabases = [ 
              "ruud"                 # Default user database
              "postgres"             # System database (required by tools)
              "grafana"              # Grafana Config Storage (Moved from SQLite)
              "oply_property_group"  # Real Estate Data Isolation
              "oply_finance"         # Financial/Crypto Data Isolation
              "oply_logistics"       # Logistics/Geo Data Isolation
              "oply_intelligence"    # AI/RAG Data Isolation
            ];
            
            # Declarative User Provisioning
            ensureUsers = [
              { name = "ruud"; ensureDBOwnership = true; }    # Admin user
              { name = "grafana"; ensureDBOwnership = true; } # Grafana service user
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
              listen_addresses = pkgs.lib.mkForce "*"; 
            };

            # Authentication (pg_hba.conf) Rules
            # Security Policy:
            # 1. Localhost (Socket) -> Trust (Peer auth). Used by Grafana (fast/secure).
            # 2. Network (Remote/K8s) -> SCRAM-SHA-256 (Strict Password, no cleartext).
            authentication = pkgs.lib.mkOverride 10 ''
              # TYPE  DATABASE        USER            ADDRESS                 METHOD
              local   all             all                                     trust
              host    all             all             127.0.0.1/32            scram-sha-256
              host    all             all             10.42.0.0/16            scram-sha-256
              host    all             all             ::1/128                 trust
              host    all             all             0.0.0.0/0               scram-sha-256
            '';
          };

          # --- LOGGING AGGREGATION: LOKI ---
          # Architecture: Centralized log storage. Receives logs from Promtail.
          services.loki = {
            enable = true;
            configuration = {
              server.http_listen_port = 3100; # Internal port for log ingestion
              auth_enabled = false; # No auth needed as it is not exposed to the public internet
              
              common = {
                ring = {
                  instance_addr = "127.0.0.1"; # Single node cluster
                  kvstore.store = "inmemory";
                };
                replication_factor = 1; # Single node, no replication needed
                path_prefix = "/var/lib/loki"; # Persistence path
              };

              # Schema definition for log storage
              schema_config.configs = [{
                from = "2024-01-01";
                store = "tsdb"; # Time Series Database format
                object_store = "filesystem"; # Store on local NVMe
                schema = "v13";
                index = { prefix = "index_"; period = "24h"; };
              }];

              storage_config.filesystem.directory = "/var/lib/loki/chunks";
            };
          };

          # --- LOG SHIPPER: PROMTAIL ---
          # Architecture: Agent that reads system logs and pushes them to Loki.
          services.promtail = {
            enable = true;
            configuration = {
              server = { http_listen_port = 9080; grpc_listen_port = 0; };
              positions.filename = "/var/lib/promtail/positions.yaml"; # Tracks read position in logs
              
              # Destination: Push to local Loki instance
              clients = [{ url = "http://127.0.0.1:3100/loki/api/v1/push"; }];

              # Job: Scrape Systemd Journal (The logs you see with journalctl)
              scrape_configs = [{
                job_name = "journal";
                journal = {
                  max_age = "12h";
                  labels = { job = "systemd-journal"; host = "manager"; };
                };
                # Relabeling: Makes the logs easier to query by service name in Grafana
                relabel_configs = [{
                  source_labels = [ "__journal__systemd_unit" ];
                  target_label = "unit";
                }];
              }];
            };
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
            port = 9090; # Internal port
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
              # Architecture: Store Grafana config (Dashboards/Users) in Postgres.
              # This ensures backups of Postgres also backup your Dashboard configurations.
              database = {
                type = "postgres";
                user = "grafana";
                name = "grafana";
                host = "/run/postgresql"; # Connect via Unix Socket (Fastest/Safest)
              };
            };
            
            # Auto-Provisioning: Automatically connect Data Sources on startup
            provision.datasources.settings.datasources = [
              {
                # Metrics Source
                name = "Prometheus";
                type = "prometheus";
                access = "proxy";
                url = "http://127.0.0.1:9090";
              }
              {
                # Logs Source (New)
                name = "Loki";
                type = "loki";
                access = "proxy";
                url = "http://127.0.0.1:3100";
              }
            ];
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
            # Disable Traefik: We will manage Ingress manually.
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
        # Dynamically load the IP from the gitignored 'local-config.nix' file.
        # This resolves the issue of purity (by importing a file) while keeping secrets separate.
        deployment.targetHost = serverConfig.serverIP;
        imports = managerModules; # What to deploy
      };
    };

    # 4. COMPATIBILITY BRIDGE
    # Generates the legacy 'Hive' object structure for older Colmena CLI versions.
    # Required to prevent "schema version" errors.
    colmenaHive = colmena.lib.makeHive self.outputs.colmena;
  };
}