{
  description = "cargo-warden dev shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        llvm = pkgs.llvmPackages_21;

        rust = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

        buildInputs = [
          rust
          llvm.clang
          llvm.bintools
          pkgs.pkg-config
          pkgs.zlib
          pkgs.bpf-linker
          pkgs.libseccomp
        ];
      in
      {
        formatter = pkgs.nixfmt-rfc-style;

        packages.bpf-prebuilt = pkgs.stdenv.mkDerivation {
          pname = "warden-bpf-prebuilt";
          version = "0.1.0";
          src = ./.;

          nativeBuildInputs = buildInputs;

          buildPhase = ''
            runHook preBuild
            export HOME=$TMPDIR/home
            export CARGO_HOME=$TMPDIR/cargo
            mkdir -p $HOME $CARGO_HOME
            export CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER=${pkgs.bpf-linker}/bin/bpf-linker
            export CARGO_TARGET_DIR=$TMPDIR/target
            cargo run -p xtask --release -- bpf-prebuilt
            runHook postBuild
          '';

          installPhase = ''
            runHook preInstall
            mkdir -p $out
            cp prebuilt.tar.gz $out/prebuilt.tar.gz
            cp prebuilt/manifest.json $out/manifest.json
            runHook postInstall
          '';

          doCheck = false;
        };

        devShells.default = pkgs.mkShell {
          packages = buildInputs ++  [ 
            pkgs.fish
            pkgs.nixfmt-rfc-style
            pkgs.nil
          ];
        };
      }
    );
}
