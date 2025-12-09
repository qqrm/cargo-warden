{ pkgs ? import <nixpkgs> {} }:

let
  llvm = pkgs.llvmPackages_latest;
in
pkgs.mkShell {
  packages = [
    pkgs.rustup
    llvm.clang
    llvm.bintools
    pkgs.pkg-config
    pkgs.zlib
    pkgs.bpf-linker
    pkgs.libseccomp
  ];
}
