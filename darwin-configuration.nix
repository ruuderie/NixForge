{ config, pkgs, ... }: {
  nix.linux-builder.enable = false;
  system.stateVersion = 6;
}