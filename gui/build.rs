use std::env;
use std::fs;
use std::path::PathBuf;

#[path = "src/res.rs"]
mod res;

fn main() {
    println!("cargo:rerun-if-changed=app.manifest");
    println!("cargo:rerun-if-changed=assets/gateinto.ico");
    println!("cargo:rerun-if-changed=src/res.rs");
    let windows = env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "windows");
    let msvc = env::var("CARGO_CFG_TARGET_ENV").is_ok_and(|e| e == "msvc");
    if !(windows && msvc) {
        return;
    }
    let ico = fs::read("assets/gateinto.ico").expect("read assets/gateinto.ico");
    let manifest = fs::read("app.manifest").expect("read app.manifest");
    let res = res::build(&ico, &manifest).expect("build the resource file");
    let path = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("gateinto-gui.res");
    fs::write(&path, res).expect("write the resource file");
    println!("cargo:rustc-link-arg-bins={}", path.display());
    println!("cargo:rustc-link-arg-bins=/MANIFEST:NO");
}
