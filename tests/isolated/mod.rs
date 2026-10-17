use std::path::PathBuf;
use std::process::Command;

pub fn no_config_home() -> PathBuf {
    std::env::temp_dir().join(format!("gateinto-no-config-{}", std::process::id()))
}

pub fn gateinto() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gateinto"));
    command
        .env("XDG_CONFIG_HOME", no_config_home())
        .env("APPDATA", no_config_home());
    command
}
