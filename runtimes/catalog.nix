# docs/quality.md#runtime-catalog-lock
{ nixpkgs, sha256, system, entries }:
let
  source = builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/${nixpkgs}.tar.gz";
    inherit sha256;
  };
  pkgs = import source {
    inherit system;
    config = { };
    overlays = [ ];
  };
  inherit (pkgs) lib;
  build = attribute:
    let package = lib.getAttrFromPath (lib.splitString "." attribute) pkgs;
    in {
      path = package.out.outPath;
      inherit (package) version;
    };
in
lib.mapAttrs (name: build) (builtins.fromJSON entries)
