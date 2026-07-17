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
            targets = [ "aarch64-unknown-linux-musl" ];
            extensions = [
              "rust-src"
              "rustfmt"
              "clippy"
              "rust-analyzer"
            ];
          };
          llvm = pkgs.llvmPackages;
        in
        {
          default = pkgs.mkShell {
            packages = [
              rustToolchain
              pkgs.curl
              pkgs.git
              pkgs.go
              pkgs.gnumake
              pkgs.grpcurl
              pkgs.jq
              pkgs.pkg-config
              pkgs.xz
              pkgs.zig
              pkgs.cargo-zigbuild
              pkgs.docker
              pkgs.docker-credential-helpers
            ]
            ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
              pkgs.dtc
              pkgs.gcc
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
        }
      );
    };
}
