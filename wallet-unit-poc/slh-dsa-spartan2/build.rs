fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let circuits_dir = std::path::PathBuf::from(&manifest_dir)
        .parent()
        .expect("Failed to get parent directory")
        .join("circom/build/cpp");

    println!("cargo::rustc-check-cfg=cfg(has_circuit_slh_dsa_1k)");

    if circuits_dir
        .join("slh_dsa_128s_poseidon_1k.cpp")
        .exists()
    {
        println!("cargo:rustc-cfg=has_circuit_slh_dsa_1k");
        println!(
            "cargo:warning=Found compiled circuit: slh_dsa_128s_poseidon_1k.cpp"
        );
    } else {
        println!(
            "cargo:warning=Missing slh_dsa_128s_poseidon_1k.cpp under {} — run `yarn compile:slh_dsa_1k` in ../circom first",
            circuits_dir.display()
        );
    }

    #[cfg(feature = "native-witness")]
    {
        let circuits_path = circuits_dir.to_str().unwrap();
        witnesscalc_adapter::build_and_link(circuits_path);

        // Embed an rpath pointing at the dylib's actual build location so the
        // binary can find libwitnesscalc_*.dylib at runtime without
        // DYLD_LIBRARY_PATH. build_and_link emits link-search=native=...
        // but not an rpath, which macOS requires for @rpath/... dylibs.
        let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
        let lib_dir = std::path::PathBuf::from(&out_dir)
            .join("witnesscalc")
            .join("package")
            .join("lib");
        if let Some(p) = lib_dir.to_str() {
            println!("cargo:rustc-link-arg=-Wl,-rpath,{}", p);
        }
    }
}
