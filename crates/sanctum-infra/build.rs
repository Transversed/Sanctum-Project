//! Build script for sanctum-infra.
//!
//! Compiles proto/sanctum.proto (wire protocol) and proto/sanctum_store.proto
//! (persistent storage) into Rust code using prost-build.
//! The generated code is placed in OUT_DIR and included via include!() macro.

fn main() {
    let protos = [
        "../../proto/sanctum.proto",
        "../../proto/sanctum_store.proto",
    ];
    for p in protos {
        println!("cargo:rerun-if-changed={p}");
    }

    prost_build::Config::new()
        .compile_protos(&protos, &["../../proto/"])
        .expect("failed to compile the protobuf schemas");
}
