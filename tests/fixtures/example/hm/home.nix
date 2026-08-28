{ config, pkgs, ... }:

{
  imports = [
    ./core/base.nix
    ./core/environment.nix
    ./ai/ollama.nix
    ./packages/desktop.nix
    ./services/nightly.nix
  ];
}
