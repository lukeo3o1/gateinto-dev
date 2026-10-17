//! Stand-in for Chrome or Edge in the agent and launch tests, built as a test
//! target without a harness so that every `cargo test` run builds it. It writes
//! into its profile, records its arguments in a fake-browser directory next to
//! the profiles directory and runs until a file named after its process id with
//! the extension .exit appears there. Run without --user-data-dir, as `cargo
//! test` does, it exits at once.

use std::path::Path;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(profile) = args
        .iter()
        .find_map(|arg| arg.strip_prefix("--user-data-dir="))
        .map(Path::new)
    else {
        return;
    };
    let default = profile.join("Default");
    std::fs::create_dir_all(&default).unwrap();
    std::fs::write(default.join("Preferences"), b"{}").unwrap();
    let dir = profile
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .join("fake-browser");
    std::fs::create_dir_all(&dir).unwrap();
    let pid = std::process::id();
    let pending = dir.join(format!("{pid}.args.tmp"));
    std::fs::write(&pending, args.join("\n")).unwrap();
    std::fs::rename(&pending, dir.join(format!("{pid}.args"))).unwrap();
    let exit = dir.join(format!("{pid}.exit"));
    while !exit.exists() {
        std::thread::sleep(Duration::from_millis(50));
    }
}
