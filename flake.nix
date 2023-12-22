{
  description = "snoop lib";

  inputs = {
    nixpkgs.url      = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, rust-overlay, ... }:
  let
  forAllSystems =
        nixpkgs.lib.genAttrs [ "x86_64-linux" "x86_64-darwin" "aarch64-linux" ];

    pkgsFor = forAllSystems (system:
        import nixpkgs {
          inherit system;
          config.allowUnfree = true;
          overlays = [ (import rust-overlay) ];
        });
  in
      {
        devShells = forAllSystems (system:
        let pkgs = pkgsFor.${system};
        in {
          default =  pkgs.mkShell {
          buildInputs = with pkgs; [
            openssl
            pkg-config
            eza
            fd
            rust-bin.beta.latest.default
          ];

          shellHook = ''
            alias ls=eza
            alias find=fd
          '';
        };
        });

      };
}