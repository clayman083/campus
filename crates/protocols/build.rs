use std::{env, path::PathBuf};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    tonic_build::configure()
        .type_attribute("passport.User", "#[derive(Hash, Eq)]")
        .build_client(true)
        .build_server(true)
        .file_descriptor_set_path(out_dir.join("passport_descriptor.bin"))
        .compile_protos(&["proto/passport.proto"], &["proto"])
        .unwrap_or_else(|e| panic!("Failed to compile protos {:?}", e));
}
