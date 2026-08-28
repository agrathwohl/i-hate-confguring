{ pkgs, ... }:

{
  systemd.user.timers.nightly-rebuild = {
    Timer.OnCalendar = "*-*-* 03:00:00";
    Install.WantedBy = [ "timers.target" ];
  };

  systemd.user.services.nightly-rebuild.Service.ExecStart = pkgs.writeShellScript "nightly-rebuild" ''
    nix flake update
    home-manager switch --flake .
  '';
}
