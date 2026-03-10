//! Build script for sanctum-infra.
//!
//! Compiles proto/sanctum.proto into Rust code using prost-build.
//! The generated code is placed in OUT_DIR and included via include!() macro.

fn main() {
    let proto_path = "../../proto/sanctum.proto";

    println!("cargo:rerun-if-changed={proto_path}");

    prost_build::Config::new()
        .compile_protos(&[proto_path], &["../../proto/"])
        .expect("failed to compile sanctum.proto");
}
