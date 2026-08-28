{
  description = "Nix development shell for silo";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    systems.url = "github:nix-systems/default";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    nixpkgs,
    systems,
    rust-overlay,
    ...
  }: let
    forEachSystem = nixpkgs.lib.genAttrs (import systems);
  in {
    devShells = forEachSystem (system: let
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };
      rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
      shells = pkgs.callPackage ./nix/devShell.nix {
        inherit rustToolchain;
        llvm = pkgs.llvmPackages;
      };
    in {
      inherit (shells) default ci release;
      kernel = pkgs.callPackage ./nix/kernelShell.nix { };
    });
  };
}
