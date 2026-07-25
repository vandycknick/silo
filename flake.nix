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
          rustToolchain = pkgs.rust-bin.stable."1.96.1".default.override {
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
          goVersion = "1.25.12";
          goPlatform =
            {
              aarch64-darwin = {
                os = "darwin";
                arch = "arm64";
                hash = "sha256-+iyIu89kvTsq7zVfAmz+xtOkoBwTL5mcj4yWTrdnFk8=";
              };
              x86_64-darwin = {
                os = "darwin";
                arch = "amd64";
                hash = "sha256-AKLnQ7grzOwDxRxLD35G1f7FIYQHX9bFGDw7s5rp+wA=";
              };
              aarch64-linux = {
                os = "linux";
                arch = "arm64";
                hash = "sha256-i1iErviWAK71sLBR+5cfEfSbuZZSHpEfMPAqZohPe9I=";
              };
              x86_64-linux = {
                os = "linux";
                arch = "amd64";
                hash = "sha256-I0got6ieDjA9JVYxDuVJ+88lPSjek3usPaE9YpQmKsE=";
              };
            }
            .${system} or (throw "unsupported Go development platform: ${system}");
           upstreamGo = pkgs.stdenvNoCC.mkDerivation {
            pname = "go";
            version = goVersion;
            src = pkgs.fetchurl {
              url = "https://go.dev/dl/go${goVersion}.${goPlatform.os}-${goPlatform.arch}.tar.gz";
              inherit (goPlatform) hash;
            };
            sourceRoot = "go";
            dontConfigure = true;
            dontBuild = true;
            dontStrip = true;
            installPhase = ''
              runHook preInstall
              mkdir -p "$out/bin" "$out/share/go"
              cp -R . "$out/share/go/"
              ln -s "$out/share/go/bin/go" "$out/bin/go"
              ln -s "$out/share/go/bin/gofmt" "$out/bin/gofmt"
              runHook postInstall
             '';
           };
           llvmTools = pkgs.llvmPackages.llvm;
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
            pkgs.zstd
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
          developmentPackages = [
            rustToolchain
            upstreamGo
            pkgs.bash
            pkgs.cacert
            pkgs.cargo-zigbuild
            pkgs.cmake
            pkgs.coreutils
            pkgs.curl
            pkgs.docker
            pkgs.docker-credential-helpers
            pkgs.git
            pkgs.gnumake
            pkgs.gnutar
            pkgs.grpcurl
            pkgs.jq
            llvmTools
            pkgs.oras
            pkgs.pkg-config
            pkgs.zig
            pkgs.zstd
          ]
          ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
            pkgs.binutils
            pkgs.e2fsprogs
            pkgs.gcc
            pkgs.libcap_ng
          ];
          developmentTools = pkgs.buildEnv {
            name = "silo-development-tools";
            paths = developmentPackages;
            pathsToLink = [
              "/bin"
              "/share"
            ];
          };
        in
        {
          default = pkgs.mkShellNoCC {
            packages = [ developmentTools ];

            shellHook = ''
              export PATH="$PWD/target/debug:$PWD/scripts:${developmentTools}/bin:/usr/bin:$PATH"
              ${pkgs.lib.optionalString pkgs.stdenv.isDarwin ''
                # stdenvNoCC still activates Darwin compiler and SDK hooks.
                unset CC CXX LD DEVELOPER_DIR SDKROOT LIBCLANG_PATH
                unset NIX_CFLAGS_COMPILE NIX_CFLAGS_COMPILE_FOR_BUILD
                unset NIX_LDFLAGS NIX_LDFLAGS_FOR_BUILD
              ''}
              echo "Entering silo dev shell. Run: make help"
            '';
          };
        }
        // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          kernel = pkgs.mkShellNoCC {
            packages = kernelPackages;
          };
        }
      );
    };
}
