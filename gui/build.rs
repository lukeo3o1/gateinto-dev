use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=app.manifest");
    println!("cargo:rerun-if-changed=app.rc");
    println!("cargo:rerun-if-changed=assets/gateinto.ico");
    println!("cargo:rerun-if-env-changed=RC");
    let windows = env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "windows");
    let msvc = env::var("CARGO_CFG_TARGET_ENV").is_ok_and(|e| e == "msvc");
    if !(windows && msvc) {
        return;
    }
    let dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let manifest = dir.join("app.manifest");
    println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
    println!(
        "cargo:rustc-link-arg-bins=/MANIFESTINPUT:{}",
        manifest.display()
    );
    println!("cargo:rustc-link-arg-bins=/MANIFESTUAC:NO");
    let res = Path::new(&env::var("OUT_DIR").unwrap()).join("app.res");
    compile_resources(&dir, &res);
    println!("cargo:rustc-link-arg-bins={}", res.display());
}

fn compile_resources(dir: &Path, res: &Path) {
    let rc = env::var("RC").unwrap_or_else(|_| "llvm-rc".into());
    let status = Command::new(&rc)
        .current_dir(dir)
        .arg("/nologo")
        .arg("/fo")
        .arg(res)
        .arg("app.rc")
        .status()
        .unwrap_or_else(|e| panic!("cannot run {rc}: {e}; set RC to a resource compiler"));
    assert!(status.success(), "{rc} failed to compile app.rc");
}
