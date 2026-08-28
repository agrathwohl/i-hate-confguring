{ config, lib, pkgs, modulesPath, ... }:

{
  boot.kernelParams = [ "threadirqs" "preempt=full" "mitigations=off" "intel_pstate=disable" ];

  systemd.sleep.settings.Sleep = { AllowSuspend = "no"; AllowHibernation = "no"; };

  systemd.watchdog.rebootTime = "30s";

  fileSystems."/mnt/media" = { device = "/dev/disk/by-uuid/0000"; fsType = "xfs"; };
}
