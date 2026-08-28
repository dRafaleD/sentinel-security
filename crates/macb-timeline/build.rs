fn main() {
    println!("cargo::rustc-check-cfg=cfg(libtsk_available)");

    #[cfg(feature = "tsk")]
    {
        let library = pkg_config::probe_library("tsk")
            .or_else(|_| pkg_config::probe_library("libtsk"));
        match library {
            Ok(library) => {
                for path in library.link_paths {
                    println!("cargo:rustc-link-search=native={}", path.display());
                }
                for lib in library.libs {
                    if let Some(name) = lib.strip_prefix("lib") {
                        println!("cargo:rustc-link-lib={name}");
                    } else {
                        println!("cargo:rustc-link-lib={lib}");
                    }
                }
                println!("cargo:rustc-cfg=libtsk_available");
            }
            Err(err) => {
                println!("cargo:warning=libtsk not found, offline image support disabled: {err}");
            }
        }

        // E01/EWF and AFF images require libewf/libaff when TSK was built with them.
        if let Ok(library) = pkg_config::probe_library("libewf") {
            for path in library.link_paths {
                println!("cargo:rustc-link-search=native={}", path.display());
            }
            for lib in library.libs {
                if let Some(name) = lib.strip_prefix("lib") {
                    println!("cargo:rustc-link-lib={name}");
                } else {
                    println!("cargo:rustc-link-lib={lib}");
                }
            }
        }

        if let Ok(library) = pkg_config::probe_library("libafflib") {
            for path in library.link_paths {
                println!("cargo:rustc-link-search=native={}", path.display());
            }
            for lib in library.libs {
                if let Some(name) = lib.strip_prefix("lib") {
                    println!("cargo:rustc-link-lib={name}");
                } else {
                    println!("cargo:rustc-link-lib={lib}");
                }
            }
        }
    }
}
