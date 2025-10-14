{
  description = "CLI tool to merge KDBX (keepass) databases";

  inputs = {
    nixpkgs = {
      url = "github:NixOS/nixpkgs";
    };
    flake-utils = {
      url = "github:numtide/flake-utils";
    };
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { self
    , nixpkgs
    , flake-utils
    , rust-overlay
    ,
    }: (
      let
        buildKeepassMerge = { rustPlatform, lib, src }: rustPlatform.buildRustPackage rec {
          pname = "keepass-merge";
          version = "main";

          inherit src;

          cargoLock = {
            lockFile = src + "/Cargo.lock";
            outputHashes = {
              # This hash need to be updated everytime you bump the version of the keepass-rs
              # library.
              "keepass-0.0.0-placeholder-version" = "sha256-K6KOHpV5VVyghuczl71NX40FghOiIGWy9jGh5yienv4=";
            };
          };

          auditable = false;

          meta = with lib; {
            description = "CLI tool to merge KDBX (keepass) databases";
            homepage = "https://github.com/louib/keepass-merge";
            license = licenses.gpl3;
          };
        };
      in
      {
        nixosModules = {
          keepassMerge = ./nix/module/default.nix;
          default = self.nixosModules.keepassMerge;
        };

        overlays = {
          default = final: prev: {
            keepass-merge = buildKeepassMerge {
              rustPlatform = final.makeRustPlatform {
                rustc = final.rust-bin.stable.latest.default;
                cargo = final.rust-bin.stable.latest.default;
              };
              lib = final.lib;
              src = ./.; # Project root
            };
            keepass-merge-script = import ./nix/module/script.nix { keepass-merge = final.keepass-merge; inherit (final) sudo coreutils writeShellApplication; inherit (final) lib; };
          };
        };
      } // flake-utils.lib.eachDefaultSystem (
        system: (
          let
            projectName = "keepass-merge";
            overlays = [ rust-overlay.overlays.default ];
            pkgs = import nixpkgs {
              inherit system overlays;
            };

            rustToolchain = pkgs.rust-bin.stable.latest.default;

            cargoPackages = [
              rustToolchain
            ];
          in
          {
            devShells = {
              default = pkgs.mkShell {
                buildInputs = cargoPackages ++ [ pkgs.shellcheck pkgs.nixpkgs-fmt pkgs.sudo pkgs.coreutils ];

                shellHook = ''
                  export RUSTFLAGS='-C target-cpu=native'
                '';
              };
            };
            packages =
              let
                inherit (pkgs) lib;
                rustPlatform = pkgs.makeRustPlatform {
                  rustc = rustToolchain;
                  cargo = rustToolchain;
                };
                keepass-merge-pkg = buildKeepassMerge {
                  inherit rustPlatform lib;
                  src = self;
                };
              in
              {
                default = keepass-merge-pkg;
                script = import ./nix/module/script.nix { keepass-merge = keepass-merge-pkg; inherit (pkgs) sudo coreutils writeShellApplication lib; };
              };
            checks = {
              build = self.packages.${system}.default;
              build-script = self.packages.${system}.script;
              #TODO comment out when keepass-rs is non git based
              # cargo-check = pkgs.runCommand "cargo-check"
              #   {
              #     src = ./.;
              #     buildInputs = [ rustToolchain ];
              #   } ''
              #   cd $src
              #   cargo check --locked
              #   touch $out
              # '';
              # cargo-clippy = pkgs.runCommand "cargo-clippy"
              #   {
              #     src = ./.;
              #     buildInputs = [ rustToolchain ];
              #   } ''
              #   cd $src
              #   cargo clippy --locked -- -D warnings
              #   touch $out
              # '';
              # cargo-test = pkgs.runCommand "cargo-test"
              #   {
              #     src = ./.;
              #     buildInputs = [ rustToolchain ];
              #   } ''
              #   cd $src
              #   cargo test --locked
              #   touch $out
              # '';
              nix-fmt = pkgs.runCommand "nix-fmt"
                {
                  src = ./.;
                } ''
                cd $src
                ${pkgs.nixpkgs-fmt}/bin/nixpkgs-fmt --check flake.nix nix/module/default.nix nix/module/script.nix
                touch $out
              '';
              shellcheck = pkgs.runCommand "shellcheck"
                {
                  src = ./.;
                } ''
                cd $src
                ${pkgs.shellcheck}/bin/shellcheck nix/module/merge_keepass.sh
                touch $out
              '';
              package-smoke-test = pkgs.runCommand "package-smoke-test"
                {
                  buildInputs = [ self.packages.${system}.default ];
                } ''
                keepass-merge --help > /dev/null
                touch $out
              '';
            };
          }
        )
      )
    );
}
