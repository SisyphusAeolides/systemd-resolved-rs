use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

fn command(program: &OsString, args: &[OsString]) -> ExitStatus {
    let status = Command::new(program)
        .args(args)
        .status()
        .unwrap_or_else(|error| panic!("failed to execute {program:?}: {error}"));
    assert!(status.success(), "command {program:?} failed with {status}");
    status
}

fn object(out_dir: &Path, name: &str) -> PathBuf {
    out_dir.join(format!("{name}.o"))
}

fn main() {
    println!("cargo:rerun-if-changed=ffi/native.c");
    println!("cargo:rerun-if-changed=ffi/native.h");
    println!("cargo:rerun-if-changed=ffi/routing.f90");

    let target = env::var("CARGO_CFG_TARGET_OS").expect("target OS is set by cargo");
    assert!(target == "linux", "systemd-resolved-rs currently supports Linux only");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"));
    fs::create_dir_all(&out_dir).expect("create build output directory");

    let cc = env::var_os("CC").unwrap_or_else(|| OsString::from("cc"));
    let ar = env::var_os("AR").unwrap_or_else(|| OsString::from("ar"));
    let native_obj = object(&out_dir, "resolved_native");
    command(
        &cc,
        &[
            OsString::from("-c"),
            OsString::from("-std=c17"),
            OsString::from("-O2"),
            OsString::from("-fPIC"),
            OsString::from("-fstack-protector-strong"),
            OsString::from("-D_FORTIFY_SOURCE=3"),
            OsString::from("-Wall"),
            OsString::from("-Wextra"),
            OsString::from("-Werror"),
            OsString::from("-Iffi"),
            OsString::from("ffi/native.c"),
            OsString::from("-o"),
            native_obj.clone().into_os_string(),
        ],
    );

    let mut objects = vec![native_obj];
    let fortran_enabled = env::var_os("CARGO_FEATURE_FORTRAN_ROUTING").is_some();
    if fortran_enabled {
        let fc = env::var_os("FC").unwrap_or_else(|| OsString::from("gfortran"));
        let fortran_obj = object(&out_dir, "resolved_routing");
        command(
            &fc,
            &[
                OsString::from("-c"),
                OsString::from("-std=f2018"),
                OsString::from("-O2"),
                OsString::from("-fPIC"),
                OsString::from("-fimplicit-none"),
                OsString::from("-Wall"),
                OsString::from("-Wextra"),
                OsString::from("-Werror"),
                OsString::from(format!("-J{}", out_dir.display())),
                OsString::from("ffi/routing.f90"),
                OsString::from("-o"),
                fortran_obj.clone().into_os_string(),
            ],
        );
        objects.push(fortran_obj);
    }

    let archive = out_dir.join("libresolved_native.a");
    let mut args = vec![OsString::from("crs"), archive.clone().into_os_string()];
    args.extend(objects.into_iter().map(PathBuf::into_os_string));
    command(&ar, &args);

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=resolved_native");
    if fortran_enabled {
        println!("cargo:rustc-link-lib=gfortran");
    }
}
