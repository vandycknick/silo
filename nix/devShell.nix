{
  pkgs,
  llvm,
}: let
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
in
  pkgs.mkShell {
    packages = [
      rustToolchain
      pkgs.go
      pkgs.grpcurl
      pkgs.zig
      pkgs.cargo-zigbuild
      pkgs.docker
      pkgs.docker-credential-helpers
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

    shellHook = ''
      workspace_root="$(pwd -P)"
      export PATH="$workspace_root/target/debug:$workspace_root/scripts:$PATH"
      export LIBCLANG_PATH="${llvm.libclang.lib}/lib"
      echo "Entering silo dev shell. Run: make build"
    '';
  }
