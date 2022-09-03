{
  description = "A very basic flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
    relic.url = "github:abueide/relic/flake";
  };

  outputs = { self, nixpkgs, flake-utils, relic }:
  flake-utils.lib.eachDefaultSystem (system:
            let pkgs = nixpkgs.legacyPackages.${system};
                chia-relic = relic.defaultPackage.${system};
                deps = with pkgs; [ libsodium cmake gmp chia-relic ];
            in rec {
            devShells.default = pkgs.mkShell {
                packages = deps;
            };
            defaultPackage = with pkgs; stdenv.mkDerivation {
              pname = "bls-signatures";
              version = "1.0.14";
              src = self;

              buildInputs = deps;

              enableParallelBuilding = true;
                cmakeFlags = [
                  "-DBUILD_BLS_TESTS=false"
                  "-DBUILD_BLS_BENCHMARKS=false"
                  "-DBUILD_BLS_PYTHON_BINDINGS=false"
                  "-DBUILD_LOCAL=true"
               ];
            };
            }
          );
}
