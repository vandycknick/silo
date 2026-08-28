{
  pkgs,
  llvm,
  rustToolchain,
}:
let
  zig = if pkgs ? zig_0_16 then pkgs.zig_0_16 else pkgs.zig;
  releasePackages = [
    rustToolchain
    pkgs.go
    pkgs.nodejs_26
    zig
    pkgs.cargo-zigbuild
    pkgs.git
    pkgs.gnumake
    pkgs.gnutar
    pkgs.oras
    pkgs.syft
    pkgs.zstd
  ];
  # Everything needed to compile, lint, and test the workspace. Deliberately
  # omits the cross-compilation and packaging tools that only release builds
  # invoke, because CI pays to download this closure on every runner.
  ciPackages = [
      rustToolchain
      pkgs.go
      pkgs.nodejs_26
      pkgs.git
      pkgs.gnumake
      pkgs.gnutar
      pkgs.zstd
    ]
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
  developmentPackages = ciPackages
    ++ [
      zig
      pkgs.cargo-zigbuild
      pkgs.oras
      pkgs.syft
      pkgs.docker
      pkgs.docker-credential-helpers
      pkgs.grpcurl
    ];
  workspaceHook = ''
    workspace_root="$(pwd -P)"
    export PATH="$workspace_root/target/debug:$workspace_root/scripts:$PATH"
    export LIBCLANG_PATH="${llvm.libclang.lib}/lib"
  '';
in
{
  default = pkgs.mkShell {
    packages = developmentPackages;

    shellHook = ''
      ${workspaceHook}
      echo "Entering silo dev shell. Run: make build" >&2
    '';
  };

  ci = pkgs.mkShell {
    packages = ciPackages;

    shellHook = workspaceHook;
  };

  release = pkgs.mkShellNoCC {
    packages = releasePackages;

    shellHook = ''
      workspace_root="$(pwd -P)"
      export PATH="$workspace_root/target/debug:$workspace_root/scripts:${pkgs.lib.makeBinPath releasePackages}:/usr/bin:/bin:/usr/sbin:/sbin"
      ${pkgs.lib.optionalString pkgs.stdenv.isLinux ''
        export CC=/usr/bin/cc
        export CXX=/usr/bin/c++
        export AR=/usr/bin/ar
        export LD=/usr/bin/ld
        export PKG_CONFIG=/usr/bin/pkg-config
      ''}
      ${pkgs.lib.optionalString pkgs.stdenv.isDarwin ''
        unset DEVELOPER_DIR SDKROOT CC CXX AR LD PKG_CONFIG
      ''}
      unset NIX_CC NIX_BINTOOLS
      unset NIX_CFLAGS_COMPILE NIX_CFLAGS_COMPILE_FOR_TARGET
      unset NIX_CFLAGS_LINK NIX_CFLAGS_LINK_FOR_TARGET
      unset NIX_LDFLAGS NIX_LDFLAGS_FOR_TARGET
      case "''${CARGO_HOME-}" in
        "$workspace_root"|"$workspace_root"/*) unset CARGO_HOME ;;
      esac
      case "''${GOCACHE-}" in
        "$workspace_root"|"$workspace_root"/*) unset GOCACHE ;;
      esac
      case "''${GOMODCACHE-}" in
        "$workspace_root"|"$workspace_root"/*) unset GOMODCACHE ;;
      esac
      unset CARGO_BUILD_TARGET
      echo "Entering silo release shell. Run: make archive" >&2
    '';
  };
}
