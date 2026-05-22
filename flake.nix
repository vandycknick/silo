{
  description = "Nix flake for bentobox development and bentoctl packaging";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    systems.url = "github:nix-systems/default";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs =
    {
      self,
      nixpkgs,
      systems,
      rust-overlay,
    }:
    let
      forEachSystem = nixpkgs.lib.genAttrs (import systems);
    in
    {
      packages = forEachSystem (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };
          bentoctlToml = fromTOML (builtins.readFile ./app/bentoctl/Cargo.toml);
          version = bentoctlToml.package.version or "0.1.0";
        in
        {
          bentoctl = pkgs.rustPlatform.buildRustPackage {
            pname = "bentobox";
            inherit version;
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;
            cargoBuildFlags = [
              "-p"
              "bentoctl"
              "-p"
              "bento-vmmon"
            ];

            postFixup = pkgs.lib.optionalString pkgs.stdenv.isDarwin ''
              /usr/bin/codesign -f --entitlements ${./runtime/bento-vmmon/vmmon.entitlements} -s - "$out/bin/vmmon"
              /usr/bin/codesign --verify --verbose=4 "$out/bin/vmmon"
            '';
          };

          bento = self.packages.${system}.bentoctl;

          default = self.packages.${system}.bentoctl;
        }
      );

      apps = forEachSystem (system: {
        bento = {
          type = "app";
          program = "${self.packages.${system}.bento}/bin/bento";
        };

        bentoctl = {
          type = "app";
          program = "${self.packages.${system}.bentoctl}/bin/bentoctl";
        };

        default = self.apps.${system}.bento;
      });

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
              pkgs.gnumake
              pkgs.pkg-config
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
              echo "Entering bentobox dev shell."
            '';
          };
        }
      );

      defaultPackage = forEachSystem (system: self.packages.${system}.default);
      defaultApp = forEachSystem (system: self.apps.${system}.default);
    };
}
