fn main() {
    // build.rs is currently empty as we rely on tropic01 crate for the tropic backend
    println!("cargo:rerun-if-changed=build.rs");
}
