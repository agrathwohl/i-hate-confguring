{
  description = "ihc - proof-first NixOS/nix-darwin + home-manager maintenance loop";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];

      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      # Tools the unit needs on PATH regardless of how it is launched.
      runtimeTools = pkgs: [
        pkgs.nix
        pkgs.git
        pkgs.coreutils
        pkgs.gnugrep
        pkgs.gawk
        pkgs.findutils
        pkgs.util-linux
        pkgs.libnotify
        pkgs.sudo
      ];

      execStart = cfg:
        "${cfg.package}/bin/ihc run"
        + nixpkgs.lib.optionalString (cfg.extraArgs != [ ])
          (" " + nixpkgs.lib.escapeShellArgs cfg.extraArgs);
    in
    {
      packages = forAllSystems (pkgs: {
        default = pkgs.python3Packages.buildPythonApplication {
          pname = "ihc";
          version = "0.1.0";
          pyproject = true;
          src = ./.;
          build-system = [ pkgs.python3Packages.setuptools ];
          doCheck = false;
          meta.mainProgram = "ihc";
        };
      });

      apps = forAllSystems (pkgs: {
        default = {
          type = "app";
          program = "${self.packages.${pkgs.stdenv.hostPlatform.system}.default}/bin/ihc";
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [ pkgs.python3 pkgs.uv ];
        };
      });

      homeModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.services.ihc;
        in
        {
          options.services.ihc = {
            enable = lib.mkEnableOption "the ihc maintenance timer";

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
              defaultText = lib.literalMD "the `ihc` package from this flake";
              description = "The ihc package to run.";
            };

            onCalendar = lib.mkOption {
              type = lib.types.str;
              default = "*-*-* 03:00:00";
              description = "systemd OnCalendar expression for the ihc timer.";
            };

            randomizedDelay = lib.mkOption {
              type = lib.types.str;
              default = "20m";
              description = "systemd RandomizedDelaySec for the ihc timer.";
            };

            extraArgs = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ ];
              description = "Extra arguments appended to `ihc run`.";
            };

            environment = lib.mkOption {
              type = lib.types.attrsOf lib.types.str;
              default = { };
              example = { IHC_FLAKE = "/etc/nixos"; IHC_SWITCH = "1"; };
              description = "Extra environment variables for the ihc unit.";
            };

            extraPath = lib.mkOption {
              type = lib.types.listOf lib.types.package;
              default = [ ];
              description = "Extra packages placed on the ihc unit's PATH.";
            };
          };

          config = lib.mkIf cfg.enable {
            systemd.user.services.ihc = {
              Unit.Description = "ihc maintenance run";

              Service = {
                Type = "oneshot";
            SuccessExitStatus = "75";  # another ihc run held the lock: skip, not a failure
                ExecStart = execStart cfg;
                Nice = 19;
                IOSchedulingClass = "idle";
                Environment =
                  lib.mapAttrsToList (n: v: "${n}=${v}") cfg.environment
                  ++ [
                    ("PATH=" + lib.makeBinPath (runtimeTools pkgs ++ cfg.extraPath)
                      + ":/run/wrappers/bin"
                      + ":/run/current-system/sw/bin"
                      + ":/etc/profiles/per-user/${config.home.username}/bin"
                      + ":${config.home.homeDirectory}/.nix-profile/bin"
                      + ":${config.home.homeDirectory}/.local/bin"
                      + ":${config.home.homeDirectory}/.npm-global/bin")
                  ];
              };
            };

            systemd.user.timers.ihc = {
              Unit.Description = "ihc maintenance timer";

              Timer = {
                OnCalendar = cfg.onCalendar;
                RandomizedDelaySec = cfg.randomizedDelay;
                Persistent = true;
              };

              Install.WantedBy = [ "timers.target" ];
            };
          };
        };

      homeManagerModules.default = self.homeModules.default;

      nixosModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.services.ihc;
        in
        {
          options.services.ihc = {
            enable = lib.mkEnableOption "the ihc maintenance timer";

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
              defaultText = lib.literalMD "the `ihc` package from this flake";
              description = "The ihc package to run.";
            };

            user = lib.mkOption {
              type = lib.types.str;
              description = "User account the ihc unit runs as. Required when enabled.";
            };

            onCalendar = lib.mkOption {
              type = lib.types.str;
              default = "*-*-* 03:00:00";
              description = "systemd OnCalendar expression for the ihc timer.";
            };

            randomizedDelay = lib.mkOption {
              type = lib.types.str;
              default = "20m";
              description = "systemd RandomizedDelaySec for the ihc timer.";
            };

            extraArgs = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ ];
              description = "Extra arguments appended to `ihc run`.";
            };

            environment = lib.mkOption {
              type = lib.types.attrsOf lib.types.str;
              default = { };
              example = { IHC_FLAKE = "/etc/nixos"; IHC_SWITCH = "1"; };
              description = "Extra environment variables for the ihc unit.";
            };

            extraPath = lib.mkOption {
              type = lib.types.listOf lib.types.package;
              default = [ ];
              description = "Extra packages placed on the ihc unit's PATH.";
            };
          };

          config = lib.mkIf cfg.enable {
            systemd.services.ihc = {
              description = "ihc maintenance run";

              serviceConfig = {
                Type = "oneshot";
            SuccessExitStatus = "75";
                User = cfg.user;
                ExecStart = execStart cfg;
                Nice = 19;
                IOSchedulingClass = "idle";
                Environment =
                  lib.mapAttrsToList (n: v: "${n}=${v}") cfg.environment
                  ++ [
                    # %U expands to the numeric UID of the unit's User.
                    "XDG_RUNTIME_DIR=/run/user/%U"
                    "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%U/bus"
                    ("PATH=" + lib.makeBinPath (runtimeTools pkgs ++ cfg.extraPath)
                      + ":/run/wrappers/bin"
                      + ":/run/current-system/sw/bin"
                      + ":/etc/profiles/per-user/${cfg.user}/bin"
                      + ":/home/${cfg.user}/.nix-profile/bin"
                      + ":/home/${cfg.user}/.local/bin"
                      + ":/home/${cfg.user}/.npm-global/bin")
                  ];
              };
            };

            systemd.timers.ihc = {
              description = "ihc maintenance timer";
              wantedBy = [ "timers.target" ];

              timerConfig = {
                OnCalendar = cfg.onCalendar;
                RandomizedDelaySec = cfg.randomizedDelay;
                Persistent = true;
              };
            };
          };
        };
    };
}
