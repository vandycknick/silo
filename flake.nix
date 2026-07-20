{
  description = "Nix development shell for silo";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    systems.url = "github:nix-systems/default";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs =
    {
      nixpkgs,
      systems,
      rust-overlay,
      ...
    }:
    let
      forEachSystem = nixpkgs.lib.genAttrs (import systems);
    in
    {
      devShells = forEachSystem (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };
          rustToolchain = pkgs.rust-bin.stable.latest.default.override {
            targets = [
              "aarch64-unknown-linux-musl"
              "x86_64-unknown-linux-musl"
            ];
            extensions = [
              "rust-src"
              "rustfmt"
              "clippy"
              "rust-analyzer"
            ];
          };
          llvm = pkgs.llvmPackages;
          kernelPackages = [
            pkgs.bash
            pkgs.cacert
            pkgs.coreutils
            pkgs.cpio
            pkgs.curl
            pkgs.diffutils
            pkgs.findutils
            pkgs.git
            pkgs.gnugrep
            pkgs.gnumake
            pkgs.gnused
            pkgs.gnutar
            pkgs.gzip
            pkgs.jq
            pkgs.oras
            pkgs.perl
            pkgs.pkg-config
            pkgs.xz
          ]
          ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
            pkgs.bc
            pkgs.binutils
            pkgs.bison
            pkgs.ccache
            pkgs.elfutils
            pkgs.flex
            pkgs.gawk
            pkgs.gcc
            pkgs.openssl
          ];
        in
        {
          default = pkgs.mkShell {
            packages = [
              rustToolchain
              pkgs.go
              pkgs.grpcurl
              pkgs.zig
              pkgs.cargo-zigbuild
              pkgs.docker
              pkgs.docker-credential-helpers
            ]
            ++ kernelPackages
            ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
              pkgs.dtc
              pkgs.libcap_ng
              pkgs.patchelf
              llvm.clang
              llvm.libclang
            ]
            ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
              pkgs.lld
              llvm.clang
              llvm.libclang
            ];

            shellHook = ''
              export PATH="$PWD/scripts:$PATH"
              export LIBCLANG_PATH="${llvm.libclang.lib}/lib"
              echo "Entering silo dev shell. Run: make build"
            '';
          };

          kernel = pkgs.mkShell {
            packages = kernelPackages;
          };
        }
      );
    };
}
