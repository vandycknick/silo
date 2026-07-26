{
  description = "Nix development shell for silo";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    systems.url = "github:nix-systems/default";
    rust-overlay.url = "github:oxalica/rust-overlay";
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
        overlays = [ (import rust-overlay) ];
      };
    in {
      default = pkgs.callPackage ./nix/devShell.nix {
        llvm = pkgs.llvmPackages;
      };
      kernel = pkgs.callPackage ./nix/kernelShell.nix { };
    });
  };
}
