{ config, pkgs, lib, ... }:

{
  imports = [
    ./hardware-configuration.nix
    ./modules/extra.nix
    <home-manager/nixos>
  ];

  system.autoUpgrade.enable = false;
  system.copySystemConfiguration = true;
  system.stateVersion = "24.05";

  boot.loader.systemd-boot.configurationLimit = 20;
  boot.kernelPackages = pkgs.linuxPackages_latest;

  nix.settings.auto-optimise-store = true;
  nix.trustedUsers = [ "root" ];

  hardware.opengl.enable = true;
  hardware.pulseaudio.enable = true;

  services.printing.enable = true;

  virtualisation.docker.enable = true;

  services.openssh.enable = true;
  services.tailscale.enable = true;

  /* services.foo.enable = true; */

  services.exampled = {
    enable = true;
    api_key = "EXAMPLE-NOT-A-REAL-KEY-000000";
    # secret_key = "should-be-ignored";
  };

  programs.nh = { enable = true; clean.enable = true; };

  system.build.exampleTarball = builtins.fetchTarball "https://example.invalid/x.tar.gz";
}
