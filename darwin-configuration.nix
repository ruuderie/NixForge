{ config, pkgs, ... }: {
  nix.linux-builder.enable = false;
  nix.enable = false;
  system.stateVersion = 6;
}