{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.services.keepassMerge;
  keepass-merge = pkgs.keepass-merge;
  merge_script = import ./script.nix { inherit keepass-merge; inherit (pkgs) sudo coreutils writeShellApplication; inherit lib; };
in
{
  options.services.keepassMerge = {
    enable = mkEnableOption "KeePass merge service for detecting sync conflicts";

    configs = mkOption {
      type = types.listOf (types.submodule {
        options = {
          path = mkOption {
            type = types.path;
            description = "Directory to monitor for sync conflict files";
          };
          name = mkOption {
            type = types.str;
            default = replaceStrings [ "/" ] [ "_" ] (toString config.path);
            description = "Name for the systemd service, defaults to path with slashes replaced by underscores";
          };
          passwordFile = mkOption {
            type = types.nullOr types.path;
            default = null;
            description = "Path to password file for this directory";
          };
        };
      });
      default = [ ];
      description = "List of directory configurations with paths, names, and optional password files";
    };

    pattern = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = ".*\\.sync-conflict-.*\\.kdbx|.* \\(conflicted copy [^)]+\\)\\.kdbx|.*_conflict_.*\\.kdbx|.*-conflict-.*\\.kdbx";
      description = "Regex pattern to match sync conflict files";
    };

    guiCommand = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "\${pkgs.alacritty}/bin/alacritty -T keepass-merge --class keepass-merge -e ";
      description = "Command to launch GUI mode of keepass-merge";
    };

    moveOnRemoval = mkOption {
      type = types.bool;
      default = false;
      description = "Move conflict files instead of deleting them";
    };

    extraArgs = mkOption {
      type = types.str;
      default = "";
      description = "Extra arguments to pass to keepass-merge";
    };

    user = mkOption {
      type = types.str;
      default = "root";
      description = "User to run the service as";
    };

    guiUser = mkOption {
      type = types.str;
      default = cfg.user;
      description = "User to launch GUI mode as (if different from the service user)";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.configs != [ ];
        message = "services.keepassMerge.configs must not be empty when the service is enabled.";
      }
      {
        assertion = cfg.user != "";
        message = "services.keepassMerge.user must not be empty.";
      }
      {
        assertion = cfg.guiUser != "";
        message = "services.keepassMerge.guiUser must not be empty.";
      }
    ];


    environment.systemPackages = with pkgs; [
      merge_script
    ];

    systemd.services = mkMerge [
      {
        "keepass-merge-monitor" = {
          description = "Monitor directories for KeePass sync conflicts";
          wantedBy = [ "multi-user.target" ];
          partOf = [ "multi-user.target" ];
          serviceConfig = {
            User = cfg.user;
            ExecStart =
              let
                monitorScript = pkgs.writeScript "keepass-monitor" ''
                  #!${pkgs.bash}/bin/bash
                  set -euo pipefail
                  echo "Starting KeePass conflict monitor for directories: ${lib.concatStringsSep " " (map (c: toString c.path) cfg.configs)}"
                  ${pkgs.inotify-tools}/bin/inotifywait -m -r -e create ${lib.concatStringsSep " " (map (c: toString c.path) cfg.configs)} |
                  while read -r dir action file; do
                    echo "Detected new file: $dir/$file"
                    ${lib.concatStringsSep "\n" (map (c: ''
                      if [ "$dir" = "${toString c.path}" ]; then
                        systemctl start "keepass-merge-${c.name}" --no-block || echo "Failed to start merge service for $dir"
                      fi
                    '') cfg.configs)}
                  done
                '';
              in
              monitorScript;
            Restart = "always";
            RestartSec = 5;
            StartLimitBurst = 3;
          };
        };
      }
      (mkMerge (map
        (c: {
          "keepass-merge-${c.name}" = {
            description = "Merge KeePass sync conflicts in ${toString c.path}";
            serviceConfig = {
              User = cfg.user;
              Type = "oneshot";
              TimeoutStartSec = 300;
              Environment = [
                "DISPLAY=:0"
                "XAUTHORITY=/home/${cfg.guiUser}/.Xauthority"
                "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u ${cfg.guiUser})/bus"
              ] ++ (optional (cfg.pattern != null) "CONFLICT_PATTERN=${cfg.pattern}")
              ++ (optional (cfg.guiCommand != null) "KEEPASS_MERGE_GUI=${cfg.guiCommand}")
              ++ (optional cfg.moveOnRemoval "KEEPASS_MOVE_ON_REMOVAL=true")
              ++ (optional (cfg.extraArgs != "") "KEEPASS_MERGE_EXTRAARGS=${cfg.extraArgs}")
              ++ (optional (c.passwordFile != null) "KEEPASS_PASSWORD_FILE=${toString c.passwordFile}");
              ExecStart = "${merge_script}/bin/merge_keepass ${toString c.path}";
            };
          };
        })
        cfg.configs))
    ];
  };
}
