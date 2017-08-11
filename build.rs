use std::env;

fn main() {
    // link to the SAPI library
    println!("cargo:rustc-link-lib=sapi");

    // if the user wants to use tcti-socket then link it in
    if env::var("CARGO_FEATURE_TCTI_SOCKET").is_ok() {
        println!("cargo:rustc-link-lib=tcti-socket");
    }

    // if the user wants to use tcti-device then link it in
    if env::var("CARGO_FEATURE_TCTI_DEVICE").is_ok() {
        println!("cargo:rustc-link-lib=tcti-device");
    }

    // add to the search path anything set in the SAPI_LIBS_PATH
    if let Ok(path) = env::var("SAPI_LIBS_PATH") {
        println!("cargo:rustc-link-search={}", path);
    }

    // add to the search path anything set in the TCTI_DEV_LIBS_PATH
    if let Ok(path) = env::var("TCTI_DEV_LIBS_PATH") {
        println!("cargo:rustc-link-search={}", path);
    }

    // add to the search path anything set in the TCTI_SOCK_LIBS_PATH
    if let Ok(path) = env::var("TCTI_SOCK_LIBS_PATH") {
        println!("cargo:rustc-link-search={}", path);
    }
}
