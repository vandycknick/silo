{ pkgs, rustToolchain, developmentShell }:
let
  msb = pkgs.stdenv.mkDerivation {
    pname = "microsandbox-perf";
    version = "0.7.15";
    src = pkgs.fetchurl {
      url = "https://github.com/superradcompany/microsandbox/releases/download/v0.7.15/microsandbox-linux-x86_64.tar.gz";
      hash = "sha256-N//Hv3srl3qwBPYg9HrkRm8CGpuIDJT0b2l8Vs9pMrc=";
    };
    sourceRoot = ".";
    nativeBuildInputs = [ pkgs.autoPatchelfHook pkgs.makeWrapper ];
    buildInputs = [ pkgs.stdenv.cc.cc.lib pkgs.openssl pkgs.zlib ];
    installPhase = ''
      runHook preInstall
      install -Dm755 "$(find . -type f -name msb -print -quit)" "$out/bin/msb"
      install -Dm755 "$(find . -type f -name libkrunfw.so.5.6.1 -print -quit)" "$out/lib/libkrunfw.so.5.6.1"
      runHook postInstall
    '';
    # msb refuses to launch when MSB_PATH or MSB_LIBKRUNFW_PATH are preset
    # ("no tested sandbox launch contract"); the loader path is enough.
    postFixup = ''
      wrapProgram "$out/bin/msb" --prefix LD_LIBRARY_PATH : "$out/lib"
    '';
    meta.platforms = [ "x86_64-linux" ];
  };
  distributionArch = if pkgs.stdenv.hostPlatform.isAarch64 then "arm64" else "amd64";
  distributionHashes = {
    amd64 = "sha256-QN8iJNQQ9yrkJcM3GHOweLvb2juLYSvpVx8OZ1HzrMg=";
    arm64 = "sha256-CdJviNLA8WG9G4v8bBI1ccw9KR3MqK9Ud7PKzE7JXnM=";
  };
  distribution = pkgs.stdenvNoCC.mkDerivation {
    pname = "distribution-perf";
    version = "3.1.2";
    src = pkgs.fetchurl {
      url = "https://github.com/distribution/distribution/releases/download/v3.1.2/registry_3.1.2_linux_${distributionArch}.tar.gz";
      hash = distributionHashes.${distributionArch};
    };
    sourceRoot = ".";
    dontFixup = true;
    installPhase = ''
      install -Dm755 registry "$out/bin/registry"
    '';
    meta.platforms = [ "x86_64-linux" "aarch64-linux" ];
  };
  competitors = pkgs.lib.optionals (pkgs.stdenv.hostPlatform.system == "x86_64-linux") [ msb ];
  kernelShell = pkgs.callPackage ./kernelShell.nix { inherit rustToolchain; };
in
pkgs.mkShell {
  inputsFrom = [ developmentShell kernelShell ];
  packages = competitors ++ [
    pkgs.uv
    pkgs.python312
    pkgs.openssl
    pkgs.sqlite
    pkgs.openssh
    pkgs.coreutils
    pkgs.curl
    pkgs.gzip
  ] ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
    distribution
    pkgs.glibc.static
    pkgs.util-linux
    pkgs.e2fsprogs
    pkgs.erofs-utils
  ];
  shellHook = ''
    export UV_PYTHON="${pkgs.python312}/bin/python3.12"
    export UV_PYTHON_DOWNLOADS=never
  '';
}
