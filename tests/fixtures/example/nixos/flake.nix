{
  description = "Example synthetic NixOS + home-manager flake fixture";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    home-manager = {
      url = "github:nix-community/home-manager";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    audio-tuning.url = "path:/opt/audio-tuning";

    pinned-tool.url = "github:example/pinned-tool/0123456789abcdef0123456789abcdef01234567";

    git-local.url = "git+file:///opt/git-local?rev=fedcba9876543210fedcba9876543210fedcba98";
  };

  outputs = { self, nixpkgs, home-manager, audio-tuning, pinned-tool, git-local, ... }:
    let
      system = "x86_64-linux";
    in
    {
      nixosConfigurations.example = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [ ./configuration.nix ];
      };

      homeConfigurations.alice = home-manager.lib.homeManagerConfiguration {
        pkgs = nixpkgs.legacyPackages.${system};
        modules = [
          @HM_DIR@/home.nix
        ];
      };
    };
}
