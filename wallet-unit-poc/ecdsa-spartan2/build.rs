fn sync_circuit_artifact(
    circuits_root: &std::path::Path,
    flat_cpp_dir: &std::path::Path,
    circuit_name: &str,
) {
    let source_dir = circuits_root.join(circuit_name).join(format!("{circuit_name}_cpp"));

    for ext in ["cpp", "dat"] {
        let src = source_dir.join(format!("{circuit_name}.{ext}"));
        let dst = flat_cpp_dir.join(format!("{circuit_name}.{ext}"));

        if src.exists() {
            if let Err(err) = std::fs::copy(&src, &dst) {
                println!(
                    "cargo:warning=Failed to sync {} -> {} ({})",
                    src.display(),
                    dst.display(),
                    err
                );
            }
        }
    }
}

fn main() {
    // Construct absolute path to circuits using CARGO_MANIFEST_DIR
    // This ensures the path resolves correctly regardless of working directory
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let circom_build_dir = std::path::PathBuf::from(&manifest_dir)
        .parent() // Go up from ecdsa-spartan2/ to wallet-unit-poc/
        .expect("Failed to get parent directory")
        .join("circom/build");
    let circuits_dir = circom_build_dir.join("cpp");

    // Keep the flat build/cpp directory in sync with canonical circom outputs.
    // This prevents stale witnesscalc artifacts when circuits are recompiled.
    if let Err(err) = std::fs::create_dir_all(&circuits_dir) {
        println!(
            "cargo:warning=Failed to create {} ({})",
            circuits_dir.display(),
            err
        );
    }

    for circuit in ["jwt", "jwt_1k", "jwt_2k", "jwt_4k", "jwt_8k", "show", "ecdsa"] {
        sync_circuit_artifact(&circom_build_dir, &circuits_dir, circuit);
    }

    println!("cargo:rerun-if-changed={}", circuits_dir.display());
    for circuit in ["jwt", "jwt_1k", "jwt_2k", "jwt_4k", "jwt_8k", "show", "ecdsa"] {
        let source_dir = circom_build_dir
            .join(circuit)
            .join(format!("{circuit}_cpp"));
        println!("cargo:rerun-if-changed={}", source_dir.display());
    }

    for circuit in [
        "jwt.cpp",
        "jwt.dat",
        "jwt_1k.cpp",
        "jwt_1k.dat",
        "jwt_2k.cpp",
        "jwt_2k.dat",
        "jwt_4k.cpp",
        "jwt_4k.dat",
        "jwt_8k.cpp",
        "jwt_8k.dat",
        "show.cpp",
        "show.dat",
    ] {
        println!("cargo:rerun-if-changed={}", circuits_dir.join(circuit).display());
    }

    // Emit cfg flags for each JWT circuit size variant that has been compiled.
    // The witness!() macro in prepare_circuit.rs uses these flags to conditionally
    // include the witness-generation function for each compiled size.
    for size in ["1k", "2k", "4k", "8k"] {
        // Declare the cfg key so rustc doesn't warn about unknown cfg names.
        println!("cargo::rustc-check-cfg=cfg(has_circuit_{})", size);

        let cpp_file = circuits_dir.join(format!("jwt_{}.cpp", size));
        if cpp_file.exists() {
            println!("cargo:rustc-cfg=has_circuit_{}", size);
            println!(
                "cargo:warning=Found compiled circuit: jwt_{}.cpp — enabling size '{}' support",
                size, size
            );
        }
    }

    // Only run witnesscalc build when the native-witness feature is enabled.
    // WASM builds use JavaScript witness generation instead.
    #[cfg(feature = "native-witness")]
    {
        use std::path::Path;
        let circuits_path = circuits_dir.to_str().unwrap();

        // Check for pre-built witnesscalc cache from build_pod.sh
        if let Ok(witnesscalc_cache) = std::env::var("WITNESSCALC_PREBUILD_CACHE") {
            let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
            let target = std::env::var("TARGET").unwrap_or_default();

            // Only apply for iOS targets
            match target.as_str() {
                "aarch64-apple-ios-sim" | "aarch64-apple-ios" | "x86_64-apple-ios" => {
                    let cache_src = Path::new(&witnesscalc_cache);
                    let target_witnesscalc = Path::new(&out_dir).join("witnesscalc");

                    // Symlink entire witnesscalc directory if cache exists and target doesn't
                    if cache_src.exists() && !target_witnesscalc.exists() {
                        #[cfg(unix)]
                        {
                            println!(
                                "cargo:warning=Using cached witnesscalc from: {}",
                                cache_src.display()
                            );
                            std::os::unix::fs::symlink(&cache_src, &target_witnesscalc).ok();
                        }
                    }
                }
                _ => {}
            }
        }

        witnesscalc_adapter::build_and_link(circuits_path);
    }
}
