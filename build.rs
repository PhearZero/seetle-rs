use std::env;

fn main() {
    // Only build libtropic when the 'tropic' feature is enabled
    if env::var("CARGO_FEATURE_TROPIC").is_err() {
        println!("cargo:rerun-if-changed=build.rs");
        return;
    }

    let dst = cmake::Config::new("libtropic_build")
        .define("LT_HELPERS", "ON")
        .define("LT_SILICON_REV", "ACAB")
        .build();

    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    // Libtropic creates a 'tropic' library
    println!("cargo:rustc-link-lib=static=tropic");
    // And 'trezor_crypto'
    println!("cargo:rustc-link-lib=static=trezor_crypto");
    // And our wrapper
    println!("cargo:rustc-link-lib=static=tropic_seelte");

    // Inform cargo about dependency change
    println!("cargo:rerun-if-changed=libtropic");
    println!("cargo:rerun-if-changed=libtropic_build/CMakeLists.txt");
}
