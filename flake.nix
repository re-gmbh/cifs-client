{
  description = "Nix flake for RE: cifs-client with cargo check in flake checks";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, crane, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        craneLib = crane.mkLib pkgs;

        # Common arguments can be set here to avoid repeating them later
        commonArgs = {
          src = craneLib.cleanCargoSource ./.;

          buildInputs = with pkgs; [
            # Add your build dependencies here
          ];

          nativeBuildInputs = with pkgs; [
            # Add your native build dependencies here
          ];
        };

        # Build *just* the cargo dependencies, so we can reuse
        # all of that work (e.g. via cachix) when running in CI
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        # Build the actual crate itself, reusing the dependency
        # artifacts from above
        cifsClient = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
        });
      in
      {
        checks = {
          # Run cargo check as part of `nix flake check`
          inherit cifsClient;

          # Add clippy check
          clippy = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          });

          # Add cargo fmt check
          fmt = craneLib.cargoFmt commonArgs;
        };

        packages.default = cifsClient;

        apps.default = flake-utils.lib.mkApp {
          drv = cifsClient;
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = builtins.attrValues self.checks.${system};

          # Additional dev shell dependencies can be added here
          packages = with pkgs; [
            rust-analyzer
            rustfmt
          ];
        };
      }
    );
}
