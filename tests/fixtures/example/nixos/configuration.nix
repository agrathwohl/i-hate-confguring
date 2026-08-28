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
  boot.kernelPackages = pkgs.linuxPackages_rt;
  boot.kernelPatches = [{
    name = "example-rt";
    patch = null;
    extraStructuredConfig = with pkgs.lib.kernel; {
      PREEMPT_RT = yes;
    };
  }];

  nix.settings.auto-optimise-store = true;
  nix.trustedUsers = [ "root" ];

  hardware.opengl.enable = true;
  hardware.pulseaudio.enable = true;

  security.rtkit.enable = true;

  services.jack.jackd.enable = true;
  services.jack.jackd.extraOptions = [ "-P95" "-R" "-dalsa" "-dhw:ExampleCard,0" "-r48000" "-p64" "-n2" ];

  services.pipewire.enable = true;
  services.pipewire.audio.enable = false;

  services.xserver.videoDrivers = [ "nvidia" ];

  virtualisation.docker.enable = true;

  services.openssh.enable = true;
  services.tailscale.enable = true;

  systemd.targets.sleep.enable = false;
  systemd.targets.suspend.enable = false;

  /* services.foo.enable = true; */

  services.exampled = {
    enable = true;
    api_key = "EXAMPLE-NOT-A-REAL-KEY-000000";
    # secret_key = "should-be-ignored";
  };

  programs.nh = { enable = true; clean.enable = true; };

  system.build.exampleTarball = builtins.fetchTarball "https://example.invalid/x.tar.gz";
}
