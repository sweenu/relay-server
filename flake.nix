{
  description = "Self-hosted document collaboration server for the Relay.md network";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs =
    { nixpkgs, ... }:
    let
      forAllSystems = nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          relay-server = pkgs.callPackage ./nix/package.nix { };
          default = pkgs.callPackage ./nix/package.nix { };
        }
      );

      nixosModules = {
        relay-server = import ./nix/module.nix;
        default = import ./nix/module.nix;
      };
    };
}
