use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

pub fn no_config_home() -> PathBuf {
    std::env::temp_dir().join(format!("gateinto-no-config-{}", std::process::id()))
}

fn credentials_prompt() -> PathBuf {
    static RUNS: AtomicU32 = AtomicU32::new(0);
    let run = RUNS.fetch_add(1, Ordering::Relaxed);
    Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "credentials-prompt-{}-{run}.txt",
        std::process::id()
    ))
}

pub fn gateinto() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gateinto"));
    command
        .env("XDG_CONFIG_HOME", no_config_home())
        .env("APPDATA", no_config_home())
        .env("GATEINTO_TEST_CREDENTIALS_FILE", credentials_prompt());
    command
}
