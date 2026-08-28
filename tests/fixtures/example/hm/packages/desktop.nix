{ pkgs, ... }:

{
  home.packages = [ pkgs.firefox pkgs.vlc ];

  programs.git = {
    enable = true;
    userName = "alice";
    userEmail = "alice@example.invalid";
  };
}
