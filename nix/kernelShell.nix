{ pkgs }:
pkgs.mkShell {
  packages = [
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
}
