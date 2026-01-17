{
  description = "NixForge - Secure Manager Node with k3s";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    disko.url = "github:nix-community/disko";
    disko.inputs.nixpkgs.follows = "nixpkgs";
    sops-nix.url = "github:Mic92/sops-nix";
    sops-nix.inputs.nixpkgs.follows = "nixpkgs";
    darwin.url = "github:LnL7/nix-darwin";
    darwin.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, disko, sops-nix, darwin, ... }@inputs: {
    nixosConfigurations.manager = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";

      modules = [
        disko.nixosModules.disko
        sops-nix.nixosModules.sops

        ({ config, pkgs, ... }: {
          nix.settings.experimental-features = [ "nix-command" "flakes" ];

          boot.loader.systemd-boot.enable = true;
          boot.loader.efi.canTouchEfiVariables = true;

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

          networking = {
            hostName = "manager";
            interfaces.enp10s0f1np1.ipv4.addresses = [{
              address = "69.164.248.38";
              prefixLength = 30;
            }];
            defaultGateway = "69.164.248.37";
            nameservers = [ "8.8.8.8" "1.1.1.1" ];
          };

          networking.firewall = {
            enable = true;
            allowedTCPPorts = [ 22 6443 80 443 ];
          };

          services.openssh = {
            enable = true;
            settings = {
              PasswordAuthentication = false;
              PermitRootLogin = "prohibit-password";
              KbdInteractiveAuthentication = false;
            };
          };

          users.users.root.openssh.authorizedKeys.keys = [
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE4qb5fQCQ5ZuyRyAKLD81yu12X2Mov0qePbpBwFwAaD"
          ];

          users.users.ruud = {
            isNormalUser = true;
            extraGroups = [ "wheel" "libvirtd" ];
            openssh.authorizedKeys.keys = [
              "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE4qb5fQCQ5ZuyRyAKLD81yu12X2Mov0qePbpBwFwAaD"
            ];
          };

          security.sudo = {
            enable = true;
            wheelNeedsPassword = false;
          };

          sops = {
            age.keyFile = "/var/lib/sops-nix/key.txt";
            defaultSopsFile = ./secrets/secrets.yaml;
          };

          services.k3s = {
            enable = true;
            role = "server";
            clusterInit = true;
            extraFlags = "--disable=traefik --kube-apiserver-arg=audit-log-path=/var/log/k3s/audit.log";
          };

          virtualisation.libvirtd.enable = true;
          programs.virt-manager.enable = true;
          users.users.root.extraGroups = [ "libvirtd" ];

          virtualisation.podman = {
            enable = true;
            dockerCompat = true;
            defaultNetwork.settings.dns_enabled = true;
          };

          environment.systemPackages = with pkgs; [
            kubectl k9s helm curl git fail2ban bandwhich restic podman-compose
          ];

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
    };

    darwinConfigurations.builder = darwin.lib.darwinSystem {
      system = "aarch64-darwin";
      modules = [ ./darwin-configuration.nix ];
    };

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