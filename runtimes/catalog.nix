# docs/quality.md#runtime-catalog-lock
{ nixpkgs, system, entries }:
let
  source = builtins.fetchTarball "https://github.com/NixOS/nixpkgs/archive/${nixpkgs}.tar.gz";
  pkgs = import source {
    inherit system;
    config = { };
    overlays = [ ];
  };
  inherit (pkgs) lib;
  build = attribute:
    let package = lib.getAttrFromPath (lib.splitString "." attribute) pkgs;
    in {
      path = package.outPath;
      inherit (package) version;
    };
in
lib.mapAttrs (name: build) (builtins.fromJSON entries)
