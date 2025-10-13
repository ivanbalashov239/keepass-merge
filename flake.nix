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
      flake-utils.lib.eachDefaultSystem (
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
                buildInputs = cargoPackages;

                shellHook = ''
                  export RUSTFLAGS='-C target-cpu=native'
                '';
              };
            };
            packages = {
              default = (pkgs.makeRustPlatform {
                rustc = rustToolchain;
                cargo = rustToolchain;
              }).buildRustPackage rec {
                pname = projectName;
                version = "main";

                src = ./.;

                cargoLock = {
                  lockFile = ./Cargo.lock;
                  outputHashes = {
                    # This hash need to be updated everytime you bump the version of the keepass-rs
                    # library.
                    "keepass-0.0.0-placeholder-version" = "sha256-K6KOHpV5VVyghuczl71NX40FghOiIGWy9jGh5yienv4=";
                  };
                };

                auditable = false;

                meta = with pkgs.lib; {
                  description = "CLI tool to merge KDBX (keepass) databases";
                  homepage = "https://github.com/louib/${projectName}";
                  license = licenses.gpl3;
                  # maintainers = [];
                };
              };
            };
          }
        )
      )
    );
}
