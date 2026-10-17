mod isolated;
use std::path::PathBuf;

use isolated::{gateinto as gateinto_command, no_config_home};

#[test]
fn prints_version() {
    let output = gateinto_command().arg("--version").output().unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("gateinto {}\n", env!("CARGO_PKG_VERSION"))
    );
}

fn gateinto(args: &[&str]) -> (bool, String) {
    let output = gateinto_command().args(args).output().unwrap();
    (
        output.status.success(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

#[test]
fn proxy_requires_an_upstream_endpoint() {
    let (success, stderr) = gateinto(&["proxy"]);
    assert!(!success);
    assert!(stderr.contains("--upstream-host"), "{stderr}");
    assert!(stderr.contains("--upstream-port"), "{stderr}");
}

#[test]
fn proxy_refuses_non_loopback_listen_address() {
    let (success, stderr) = gateinto(&[
        "proxy",
        "--listen",
        "0.0.0.0:0",
        "--upstream-host",
        "127.0.0.1",
        "--upstream-port",
        "9",
    ]);
    assert!(!success);
    assert!(
        stderr.contains("--unsafe-allow-non-loopback-listen"),
        "{stderr}"
    );
}

#[test]
fn proxy_reports_unreadable_ca_file() {
    let (success, stderr) = gateinto(&[
        "proxy",
        "--upstream-host",
        "127.0.0.1",
        "--upstream-port",
        "9",
        "--ca-file",
        "/nonexistent/gateinto-ca.pem",
    ]);
    assert!(!success);
    assert!(stderr.contains("/nonexistent/gateinto-ca.pem"), "{stderr}");
}

#[test]
fn proxy_rejects_zero_limits_and_ports() {
    for (flag, value) in [
        ("--upstream-port", "0"),
        ("--max-tunnels", "0"),
        ("--max-header-bytes", "0"),
        ("--connect-timeout-secs", "0"),
        ("--idle-timeout-secs", "0"),
    ] {
        let mut args = vec![
            "proxy",
            "--upstream-host",
            "127.0.0.1",
            "--upstream-port",
            "9",
        ];
        args.extend([flag, value]);
        let (success, stderr) = gateinto(&args);
        assert!(!success, "{flag}");
        assert!(stderr.contains(flag), "{stderr}");
    }
}

#[cfg(not(windows))]
#[test]
fn key_commands_require_windows() {
    for args in [
        &["key", "init"][..],
        &["key", "info"],
        &["key", "info", "--name", "other", "--spki-out", "unused.der"],
        &["key", "info", "--client-cert-file", "unused.pem"],
        &[
            "key",
            "init",
            "--backend",
            "software",
            "--no-software-fallback",
        ],
        &["key", "init", "--software-fallback"],
    ] {
        let (success, stderr) = gateinto(args);
        assert!(!success, "{args:?}");
        assert!(
            stderr.contains("device keys are only supported on Windows"),
            "{stderr}"
        );
    }
}

#[test]
fn key_commands_reject_an_empty_name() {
    for command in ["init", "info"] {
        let (success, stderr) = gateinto(&["key", command, "--name", ""]);
        assert!(!success);
        assert!(stderr.contains("key name must not be empty"), "{stderr}");
    }
}

fn proxy_args<'a>(extra: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec![
        "proxy",
        "--upstream-host",
        "127.0.0.1",
        "--upstream-port",
        "9",
        "--listen",
        "127.0.0.1:0",
    ];
    args.extend_from_slice(extra);
    args
}

#[test]
fn proxy_rejects_an_unknown_client_certificate_mode() {
    let (success, stderr) = gateinto(&proxy_args(&["--client-certificate", "sometimes"]));
    assert!(!success);
    assert!(stderr.contains("--client-certificate"), "{stderr}");
    for mode in ["optional", "required", "off"] {
        assert!(stderr.contains(mode), "{stderr}");
    }
}

#[test]
fn proxy_rejects_an_empty_key_name() {
    let (success, stderr) = gateinto(&proxy_args(&["--key-name", ""]));
    assert!(!success);
    assert!(stderr.contains("key name must not be empty"), "{stderr}");
}

#[test]
fn self_signed_client_cert_and_client_cert_file_are_exclusive_flags() {
    for command in ["proxy", "check-upstream"] {
        let (success, stderr) = gateinto(&[
            command,
            "--upstream-host",
            "127.0.0.1",
            "--upstream-port",
            "9",
            "--self-signed-client-cert",
            "--client-cert-file",
            "client.pem",
        ]);
        assert!(!success, "{command}");
        assert!(stderr.contains("cannot be used with"), "{stderr}");
        assert!(stderr.contains("--self-signed-client-cert"), "{stderr}");
        assert!(stderr.contains("--client-cert-file"), "{stderr}");
    }
}

#[cfg(not(windows))]
#[test]
fn proxy_requiring_a_client_certificate_fails_off_windows() {
    for extra in [
        &["--client-certificate", "required"][..],
        &[
            "--client-certificate",
            "required",
            "--self-signed-client-cert",
        ],
        &[
            "--client-certificate",
            "required",
            "--client-cert-file",
            "/nonexistent/gateinto-client.pem",
        ],
    ] {
        let (success, stderr) = gateinto(&proxy_args(extra));
        assert!(!success, "{extra:?}");
        assert!(
            stderr.contains("error: device keys are only supported on Windows"),
            "{stderr}"
        );
    }
}

#[cfg(windows)]
#[test]
fn proxy_requiring_a_client_certificate_fails_without_the_device_key() {
    let (success, stderr) = gateinto(&proxy_args(&[
        "--client-certificate",
        "required",
        "--key-name",
        "gateinto-test-missing-device-key",
    ]));
    assert!(!success);
    assert!(
        stderr.contains("no device key named \"gateinto-test-missing-device-key\""),
        "{stderr}"
    );
}

#[test]
fn proxy_rejects_an_unknown_tls_mode() {
    let (success, stderr) = gateinto(&proxy_args(&["--tls-mode", "hybrid"]));
    assert!(!success);
    assert!(stderr.contains("--tls-mode"), "{stderr}");
    for mode in ["hybrid_preferred", "hybrid_required", "classical_only"] {
        assert!(stderr.contains(mode), "{stderr}");
    }
}

fn help(args: &[&str]) -> String {
    let output = gateinto_command()
        .args(args)
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success(), "{args:?}");
    String::from_utf8(output.stdout).unwrap()
}

fn assert_flag_default(help: &str, flag: &str, default: impl std::fmt::Display) {
    let lines: Vec<&str> = help.lines().map(str::trim_start).collect();
    let start = lines
        .iter()
        .position(|line| line.split_whitespace().next() == Some(flag))
        .unwrap_or_else(|| panic!("{flag} missing from help:\n{help}"));
    let entry: Vec<&str> = lines[start..]
        .iter()
        .enumerate()
        .take_while(|(i, line)| *i == 0 || !line.starts_with('-'))
        .map(|(_, line)| *line)
        .collect();
    assert!(
        entry.join(" ").contains(&format!("[default: {default}]")),
        "{flag} should document [default: {default}]:\n{help}"
    );
}

#[test]
fn help_defaults_match_the_real_defaults() {
    use gateinto::config::{DeviceKeySettings, LimitSettings};
    use gateinto::identity::client_cert::ClientCertificateMode;
    use gateinto::identity::device_key::DEFAULT_KEY_NAME;
    use gateinto::proxy::DEFAULT_LISTEN;
    use gateinto::tls::TlsMode;

    let limits = LimitSettings::default();
    let device_key = DeviceKeySettings::default();
    let client_certificate = format!("{:?}", ClientCertificateMode::default()).to_lowercase();

    let proxy = help(&["proxy"]);
    assert_flag_default(&proxy, "--listen", DEFAULT_LISTEN);
    assert_flag_default(&proxy, "--max-tunnels", limits.max_concurrent_tunnels);
    assert_flag_default(&proxy, "--max-header-bytes", limits.header_max_bytes);
    assert_flag_default(
        &proxy,
        "--connect-timeout-secs",
        limits.connect_timeout_seconds,
    );
    assert_flag_default(&proxy, "--idle-timeout-secs", limits.idle_timeout_seconds);
    for upstream in [proxy, help(&["check-upstream"])] {
        assert_flag_default(&upstream, "--tls-mode", TlsMode::default());
        assert_flag_default(&upstream, "--client-certificate", &client_certificate);
        assert_flag_default(&upstream, "--key-name", DEFAULT_KEY_NAME);
    }
    for command in ["init", "info"] {
        assert_flag_default(&help(&["key", command]), "--name", DEFAULT_KEY_NAME);
    }
    assert_flag_default(&help(&["key", "init"]), "--backend", device_key.preferred);
}

#[test]
fn check_upstream_gateway_needs_a_configured_gateway() {
    let (success, stderr) = gateinto(&[
        "check-upstream",
        "--gateway",
        "office",
        "--upstream-host",
        "127.0.0.1",
        "--upstream-port",
        "9",
    ]);
    assert!(!success);
    assert!(
        stderr.contains(
            "error: --gateway names the unknown gateway \"office\"; configured gateways: none"
        ),
        "{stderr}"
    );
}

fn gateinto_without_terminal(args: &[&str]) -> (bool, String, String) {
    let output = gateinto_command()
        .args(args)
        .env("GATEINTO_INSTANCE", format!("cli-{}", std::process::id()))
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    (
        output.status.success(),
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

const SPKI_PREFIX: &str = "0123456789abcdef";

#[test]
fn reset_requires_the_purge_flag() {
    let (success, _, stderr) = gateinto_without_terminal(&["reset", "--confirm-spki", SPKI_PREFIX]);
    assert!(!success);
    assert!(stderr.contains("--purge-device-identity"), "{stderr}");
}

#[test]
fn reset_rejects_a_short_or_non_hex_spki_confirmation() {
    for value in ["0123456789abcde", "purge", "0123456789abcdeg", ""] {
        let (success, _, stderr) = gateinto_without_terminal(&[
            "reset",
            "--purge-device-identity",
            "--confirm-spki",
            value,
        ]);
        assert!(!success, "{value}");
        assert!(
            stderr.contains("16 to 64 hexadecimal digits"),
            "{value}: {stderr}"
        );
    }
}

#[test]
fn reset_without_a_terminal_needs_confirm_spki_and_touches_nothing() {
    let (success, stdout, stderr) =
        gateinto_without_terminal(&["reset", "--purge-device-identity"]);
    assert!(!success);
    assert!(stdout.is_empty(), "{stdout}");
    assert_eq!(
        stderr,
        "error: refusing to delete the device key without confirmation: no terminal to ask on; \
         pass --confirm-spki with at least the first 16 hex digits of the spki-sha256 shown by \
         `gateinto status`\n"
    );
}

#[test]
fn reset_deletes_a_config_file_only_when_named_or_at_the_default_location() {
    let (success, _, stderr) = gateinto_without_terminal(&[
        "reset",
        "--purge-device-identity",
        "--purge-config",
        "--confirm-spki",
        SPKI_PREFIX,
    ]);
    assert!(!success);
    assert!(
        stderr.contains(&format!(
            "--purge-config found no config file named with --config or at {}; nothing was \
             deleted",
            default_config(&no_config_home()).display()
        )),
        "{stderr}"
    );
}

#[test]
fn reset_refuses_to_delete_a_file_that_is_not_a_gateinto_config() {
    let path = std::env::temp_dir().join(format!("gateinto-not-config-{}.txt", std::process::id()));
    std::fs::write(&path, "important = \"data\"\n").unwrap();
    let (success, _, stderr) = gateinto_without_terminal(&[
        "reset",
        "--purge-device-identity",
        "--purge-config",
        "--config",
        path.to_str().unwrap(),
        "--confirm-spki",
        SPKI_PREFIX,
    ]);
    let kept = path.exists();
    let _ = std::fs::remove_file(&path);
    assert!(!success);
    assert!(kept);
    assert!(stderr.contains("unknown field"), "{stderr}");
}

#[test]
fn setup_and_status_check_the_config_before_touching_the_key() {
    let path =
        std::env::temp_dir().join(format!("gateinto-bad-config-{}.toml", std::process::id()));
    std::fs::write(&path, "[gateways.main]\nport = \"x\"\n").unwrap();
    for command in ["setup", "status"] {
        let (success, stdout, stderr) =
            gateinto_without_terminal(&[command, "--config", path.to_str().unwrap()]);
        assert!(!success, "{command}");
        assert!(!stdout.contains("device-key"), "{command}: {stdout}");
        assert!(
            stderr.contains(path.to_str().unwrap()),
            "{command}: {stderr}"
        );
    }
    let _ = std::fs::remove_file(&path);
}

#[cfg(not(windows))]
#[test]
fn setup_requires_windows() {
    let (success, _, stderr) = gateinto_without_terminal(&["setup"]);
    assert!(!success);
    assert!(
        stderr.contains("device keys are only supported on Windows"),
        "{stderr}"
    );
}

#[cfg(not(windows))]
#[test]
fn status_is_read_only_and_reports_what_it_can() {
    let (success, stdout, stderr) = gateinto_without_terminal(&["status"]);
    assert!(success, "{stdout}{stderr}");
    assert_eq!(
        stdout,
        format!(
            "key-name: gateinto-device-v1\n\
             device-key: unavailable: device keys are only supported on Windows\n\
             config: none (no file at {}; pass --config to use another file)\n\
             device-session: none\n\
             agent: not running\n\
             uri-handler: not supported on this platform\n",
            default_config(&no_config_home()).display()
        )
    );
}

fn default_config(home: &std::path::Path) -> PathBuf {
    if cfg!(windows) {
        home.join("Gateinto").join("gateinto.toml")
    } else {
        home.join("gateinto").join("gateinto.toml")
    }
}

#[test]
fn status_reads_the_config_file_at_the_default_location() {
    let home = std::env::temp_dir().join(format!("gateinto-cli-config-{}", std::process::id()));
    let path = default_config(&home);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        "[gateways.main]\nhost = \"proxy.example.com\"\nport = 443\n",
    )
    .unwrap();

    let output = isolated::gateinto()
        .args(["status"])
        .env("XDG_CONFIG_HOME", &home)
        .env("APPDATA", &home)
        .env("GATEINTO_INSTANCE", format!("cli-{}", std::process::id()))
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&home);

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(output.status.success(), "{stdout}");
    assert!(
        stdout.contains(&format!(
            "config: {} (default location)\ngateway: main: proxy.example.com:443\n",
            path.display()
        )),
        "{stdout}"
    );
}

#[test]
fn commands_log_which_default_config_file_they_loaded() {
    let home = std::env::temp_dir().join(format!("gateinto-cli-log-{}", std::process::id()));
    let path = default_config(&home);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        "[gateways.main]\nhost = \"127.0.0.1\"\nport = 9\nclient_certificate = \"off\"\n",
    )
    .unwrap();

    let output = isolated::gateinto()
        .args(["check-upstream"])
        .env("XDG_CONFIG_HOME", &home)
        .env("APPDATA", &home)
        .env("RUST_LOG", "info")
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&home);

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("using the default config file")
            && stderr.contains(&path.display().to_string()),
        "{stderr}"
    );
}

#[test]
fn reset_yes_only_works_together_with_purge_config() {
    let (success, _, stderr) =
        gateinto_without_terminal(&["reset", "--purge-device-identity", "--yes"]);
    assert!(!success);
    assert!(stderr.contains("--purge-config"), "{stderr}");
}

#[test]
fn reset_help_says_which_config_file_is_deleted() {
    let help = help(&["reset"]);
    assert!(
        help.contains("Also delete the config file named with --config, or else the default"),
        "{help}"
    );
}

#[cfg(windows)]
#[test]
fn reset_deletes_only_the_config_file_when_no_key_exists_and_yes_is_given() {
    let path =
        std::env::temp_dir().join(format!("gateinto-config-only-{}.toml", std::process::id()));
    std::fs::write(
        &path,
        "[device_key]\nname = \"gateinto-test-missing-reset-key\"\n",
    )
    .unwrap();
    let config = path.to_str().unwrap();

    let (success, _, stderr) = gateinto_without_terminal(&[
        "reset",
        "--purge-device-identity",
        "--purge-config",
        "--config",
        config,
    ]);
    assert!(!success);
    assert!(path.exists(), "{stderr}");

    let (success, stdout, stderr) = gateinto_without_terminal(&[
        "reset",
        "--purge-device-identity",
        "--purge-config",
        "--config",
        config,
        "--yes",
    ]);
    let kept = path.exists();
    let _ = std::fs::remove_file(&path);
    assert!(success, "{stdout}{stderr}");
    assert!(!kept);
    assert!(
        stdout.contains(
            "no device key named \"gateinto-test-missing-reset-key\"; no key was deleted"
        ),
        "{stdout}"
    );
    assert!(stdout.contains("deleted config file"), "{stdout}");
}

#[cfg(windows)]
#[test]
fn reset_with_yes_and_no_terminal_keeps_an_existing_key() {
    use gateinto::identity::device_key::{self, Backend, InitOptions, KeyName};
    use gateinto::identity::windows_cng::{CngStore, SOFTWARE_KEY_STORAGE_PROVIDER, delete_key};

    struct TestKey(KeyName);

    impl Drop for TestKey {
        fn drop(&mut self) {
            let _ = delete_key(SOFTWARE_KEY_STORAGE_PROVIDER, self.0.as_str());
        }
    }

    let key = TestKey(
        format!("gateinto-test-reset-yes-{}", std::process::id())
            .parse()
            .unwrap(),
    );
    let options = InitOptions {
        backend: Backend::Software,
        ..InitOptions::default()
    };
    let (created, _) = device_key::init(&CngStore, &key.0, options).unwrap();
    let path = std::env::temp_dir().join(format!("gateinto-reset-yes-{}.toml", std::process::id()));
    std::fs::write(&path, format!("[device_key]\nname = \"{}\"\n", key.0)).unwrap();

    let (success, stdout, stderr) = gateinto_without_terminal(&[
        "reset",
        "--purge-device-identity",
        "--purge-config",
        "--config",
        path.to_str().unwrap(),
        "--yes",
    ]);
    let kept_config = path.exists();
    let _ = std::fs::remove_file(&path);

    assert!(!success, "{stdout}");
    assert!(
        stderr.contains("refusing to delete the device key without confirmation: no terminal"),
        "{stderr}"
    );
    assert!(kept_config);
    let (still, _) = device_key::info(&CngStore, &key.0).unwrap();
    assert_eq!(still.fingerprint(), created.fingerprint());
}
