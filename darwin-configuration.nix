{ config, pkgs, ... }: {
  nix.linux-builder.enable = true;
  system.stateVersion = 6;
}