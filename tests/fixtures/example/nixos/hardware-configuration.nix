{ config, lib, pkgs, modulesPath, ... }:

{
  boot.kernelParams = [ "quiet" ];

  systemd.watchdog.rebootTime = "30s";

  fileSystems."/mnt/media" = { device = "/dev/disk/by-uuid/0000"; fsType = "xfs"; };
}
