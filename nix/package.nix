{
  lib,
  rustPlatform,
}:

rustPlatform.buildRustPackage rec {
  pname = "relay-server";
  version = "0.9.0";

  src = lib.fileset.toSource {
    root = ./..;
    fileset = lib.fileset.intersection (lib.fileset.fromSource (lib.sources.cleanSource ./..)) (
      lib.fileset.unions [
        ./../crates/Cargo.toml
        ./../crates/Cargo.lock
        ./../crates/relay
        ./../crates/y-sweet-core
        ./../crates/y-sign
      ]
    );
  };

  cargoRoot = "crates";
  buildAndTestSubdir = "crates";
  cargoHash = "sha256-r69vyDokrexfaZ655J6kTWJfZRl1BiV/1LmkzVgLirY=";

  postPatch = ''
    cat > crates/relay/build.rs << 'EOF'
    fn main() {
        println!("cargo:rustc-env=GIT_VERSION=${version}");
    }
    EOF
  '';

  meta = {
    description = "Self-hosted document collaboration server for the Relay.md network";
    homepage = "https://github.com/No-Instructions/relay-server";
    license = lib.licenses.mit;
    mainProgram = "relay";
  };
}
