mod isolated;
use std::path::PathBuf;

use isolated::{gateinto as gateinto_command, no_config_home};

#[test]
fn prints_version() {
    let output = gateinto_command().arg("--version").output().unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!(
            "gateinto {}\n",
            option_env!("GATEINTO_BUILD_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
        )
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
fn the_removed_proxy_command_is_rejected() {
    let (success, stderr) = gateinto(&["proxy"]);
    assert!(!success);
    assert!(
        stderr.contains("unrecognized subcommand 'proxy'"),
        "{stderr}"
    );
    let output = gateinto_command().arg("--help").output().unwrap();
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(
        !help
            .lines()
            .any(|line| line.trim_start().starts_with("proxy ")),
        "{help}"
    );
    assert!(!help.contains("device session"), "{help}");
}

const UPSTREAM_COMMANDS: [&[&str]; 2] = [&["check-upstream"], &["session", "browser"]];

fn upstream_args<'a>(command: &[&'a str], extra: &[&'a str]) -> Vec<&'a str> {
    let mut args = command.to_vec();
    args.extend(["--upstream-host", "127.0.0.1", "--upstream-port", "9"]);
    args.extend_from_slice(extra);
    args
}

#[test]
fn upstream_commands_report_an_unreadable_ca_file() {
    for command in UPSTREAM_COMMANDS {
        let (success, stderr) = gateinto(&upstream_args(
            command,
            &["--ca-file", "/nonexistent/gateinto-ca.pem"],
        ));
        assert!(!success, "{command:?}");
        assert!(stderr.contains("/nonexistent/gateinto-ca.pem"), "{stderr}");
    }
}

#[test]
fn upstream_commands_reject_a_zero_port() {
    for command in UPSTREAM_COMMANDS {
        let (success, stderr) = gateinto(&upstream_args(command, &["--upstream-port", "0"]));
        assert!(!success, "{command:?}");
        assert!(stderr.contains("--upstream-port"), "{stderr}");
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

#[test]
fn upstream_commands_reject_an_unknown_client_certificate_mode() {
    for command in UPSTREAM_COMMANDS {
        let (success, stderr) = gateinto(&upstream_args(
            command,
            &["--client-certificate", "sometimes"],
        ));
        assert!(!success, "{command:?}");
        assert!(stderr.contains("--client-certificate"), "{stderr}");
        for mode in ["optional", "required", "off"] {
            assert!(stderr.contains(mode), "{stderr}");
        }
    }
}

#[test]
fn upstream_commands_reject_an_empty_key_name() {
    for command in UPSTREAM_COMMANDS {
        let (success, stderr) = gateinto(&upstream_args(command, &["--key-name", ""]));
        assert!(!success, "{command:?}");
        assert!(stderr.contains("key name must not be empty"), "{stderr}");
    }
}

#[test]
fn self_signed_client_cert_and_client_cert_file_are_exclusive_flags() {
    for command in UPSTREAM_COMMANDS {
        let (success, stderr) = gateinto(&upstream_args(
            command,
            &[
                "--self-signed-client-cert",
                "--client-cert-file",
                "client.pem",
            ],
        ));
        assert!(!success, "{command:?}");
        assert!(stderr.contains("cannot be used with"), "{stderr}");
        assert!(stderr.contains("--self-signed-client-cert"), "{stderr}");
        assert!(stderr.contains("--client-cert-file"), "{stderr}");
    }
}

#[cfg(not(windows))]
#[test]
fn requiring_a_client_certificate_fails_off_windows() {
    for command in UPSTREAM_COMMANDS {
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
            let (success, stderr) = gateinto(&upstream_args(command, extra));
            assert!(!success, "{command:?} {extra:?}");
            assert!(
                stderr.contains("error: device keys are only supported on Windows"),
                "{stderr}"
            );
        }
    }
}

#[cfg(windows)]
#[test]
fn requiring_a_client_certificate_fails_without_the_device_key() {
    for command in UPSTREAM_COMMANDS {
        let (success, stderr) = gateinto(&upstream_args(
            command,
            &[
                "--client-certificate",
                "required",
                "--key-name",
                "gateinto-test-missing-device-key",
            ],
        ));
        assert!(!success, "{command:?}");
        assert!(
            stderr.contains("no device key named \"gateinto-test-missing-device-key\""),
            "{stderr}"
        );
    }
}

#[test]
fn upstream_commands_reject_an_unknown_tls_mode() {
    for command in UPSTREAM_COMMANDS {
        let (success, stderr) = gateinto(&upstream_args(command, &["--tls-mode", "hybrid"]));
        assert!(!success, "{command:?}");
        assert!(stderr.contains("--tls-mode"), "{stderr}");
        for mode in ["hybrid_preferred", "hybrid_required", "classical_only"] {
            assert!(stderr.contains(mode), "{stderr}");
        }
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
    use gateinto::config::DeviceKeySettings;
    use gateinto::identity::client_cert::ClientCertificateMode;
    use gateinto::identity::device_key::DEFAULT_KEY_NAME;
    use gateinto::tls::TlsMode;

    let device_key = DeviceKeySettings::default();
    let client_certificate = format!("{:?}", ClientCertificateMode::default()).to_lowercase();

    for command in UPSTREAM_COMMANDS {
        let upstream = help(command);
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
            "--purge-config found no config file named with --config or at {}, and no gateways \
             added from links; nothing was deleted",
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
             linked-gateways: none (no directory at {})\n\
             agent: not running\n\
             uri-handler: not supported on this platform\n",
            default_config(&no_config_home()).display(),
            default_config(&no_config_home())
                .with_file_name("gateways")
                .display()
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
            "config: {} (default location)\ngateway: main: proxy.example.com:443, route gateway (config)\n",
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

struct Home(PathBuf);

impl Home {
    fn new(name: &str) -> Self {
        let home = std::env::temp_dir().join(format!("gateinto-cli-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let config = default_config(&home);
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::fs::write(
            &config,
            "[gateways.main]\nhost = \"proxy.example.com\"\nport = 443\n\
             portal_url = \"https://portal.example.com/?token=secret\"\n",
        )
        .unwrap();
        let home = Self(home);
        std::fs::create_dir(home.linked()).unwrap();
        home.plant(
            "proxy.newco.example_8443.toml",
            "name = \"newco\"\nhost = \"proxy.newco.example\"\nport = 8443\n\
             portal_url = \"https://portal.newco.example/home\"\napproved_at = 1\n",
        );
        home.plant(
            "10.0.0.1.toml",
            "name = \"other\"\nhost = \"10.0.0.1\"\nport = 443\n\
             portal_url = \"https://other.example/\"\nroute = \"mixed\"\n",
        );
        home
    }

    fn linked(&self) -> PathBuf {
        default_config(&self.0).with_file_name("gateways")
    }

    fn plant(&self, file: &str, text: &str) -> PathBuf {
        let path = self.linked().join(file);
        std::fs::write(&path, text).unwrap();
        path
    }

    fn run(&self, args: &[&str]) -> (bool, String, String) {
        let output = isolated::gateinto()
            .args(args)
            .env("XDG_CONFIG_HOME", &self.0)
            .env("APPDATA", &self.0)
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
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn gateway_list_shows_where_each_gateway_comes_from() {
    let home = Home::new("gateway-list");
    let (success, stdout, stderr) = home.run(&["gateway", "list"]);
    assert!(success, "{stderr}");
    assert_eq!(
        stdout,
        "main: proxy.example.com:443, portal https://portal.example.com, route gateway (config)\n\
         newco: proxy.newco.example:8443, portal https://portal.newco.example, route gateway (linked)\n\
         other: 10.0.0.1:443, portal https://other.example, route mixed (linked)\n"
    );
}

#[test]
fn status_marks_linked_gateways() {
    let home = Home::new("status-linked");
    let (success, stdout, stderr) = home.run(&["status"]);
    assert!(success, "{stderr}");
    assert!(
        stdout.contains(&format!(
            "gateway: main: proxy.example.com:443, route gateway (config)\nlinked-gateways: {}\n\
             gateway: newco: proxy.newco.example:8443, route gateway (linked)\n\
             gateway: other: 10.0.0.1:443, route mixed (linked)\n",
            home.linked().display()
        )),
        "{stdout}"
    );
    assert!(
        !stdout.contains("secret") && !stdout.contains("/home"),
        "{stdout}"
    );
}

#[test]
fn gateway_forget_removes_only_gateways_added_from_links() {
    let home = Home::new("gateway-forget");

    let (success, _, stderr) = home.run(&["gateway", "forget", "main"]);
    assert!(!success);
    assert!(stderr.contains("config file"), "{stderr}");
    let (success, _, stderr) = home.run(&["gateway", "forget", "nope"]);
    assert!(!success);
    assert!(
        stderr.contains("no gateway added from a link named \"nope\""),
        "{stderr}"
    );

    let (success, stdout, stderr) = home.run(&["gateway", "forget", "newco"]);
    assert!(success, "{stderr}");
    assert!(stdout.contains("removed the gateway \"newco\""), "{stdout}");
    let (_, stdout, _) = home.run(&["gateway", "list"]);
    assert_eq!(
        stdout,
        "main: proxy.example.com:443, portal https://portal.example.com, route gateway (config)\n\
         other: 10.0.0.1:443, portal https://other.example, route mixed (linked)\n"
    );
    let config = std::fs::read_to_string(default_config(&home.0)).unwrap();
    assert!(config.contains("[gateways.main]"), "{config}");
}

const DAMAGED: &str = "name = \"broken\"\nhost = \"x.example\"\nport = 443\n\
                       portal_url = \"https://x.example/\"\nca_file = \"y\"\n";

#[test]
fn a_damaged_gateway_file_disables_only_its_own_gateway() {
    let home = Home::new("gateway-damaged");
    let broken = home.plant("x.example.toml", DAMAGED);
    let (success, stdout, stderr) = home.run(&["gateway", "list"]);
    assert!(success, "{stderr}");
    assert!(
        stdout.starts_with(
            "main: proxy.example.com:443, portal https://portal.example.com, route gateway (config)\n\
             newco: proxy.newco.example:8443, portal https://portal.newco.example, route gateway (linked)\n\
             other: 10.0.0.1:443, portal https://other.example, route mixed (linked)\n"
        ),
        "{stdout}"
    );
    let error = format!("linked-gateway: error: {}: ", broken.display());
    assert!(stdout.contains(&error), "{stdout}");
    assert!(stdout.contains("ca_file"), "{stdout}");

    let (success, _, stderr) = home.run(&["gateway", "forget", "broken"]);
    assert!(!success);
    assert!(stderr.contains("damaged file"), "{stderr}");
    assert!(broken.exists());
}

#[test]
fn status_reports_a_damaged_gateway_file_and_continues() {
    let home = Home::new("status-damaged");
    let broken = home.plant("x.example.toml", DAMAGED);
    let (success, stdout, stderr) = home.run(&["status"]);
    assert!(success, "{stdout}{stderr}");
    assert!(
        stdout.contains(&format!(
            "linked-gateways: {}\ngateway: newco: proxy.newco.example:8443, route gateway (linked)\n\
             gateway: other: 10.0.0.1:443, route mixed (linked)\nlinked-gateway: error: {}: ",
            home.linked().display(),
            broken.display()
        )),
        "{stdout}"
    );
    assert!(stdout.contains("\nagent: "), "{stdout}");
}

#[test]
fn an_unusable_gateways_directory_is_reported_by_status_and_refused_by_list() {
    let home = Home::new("status-unusable");
    std::fs::remove_dir_all(home.linked()).unwrap();
    std::fs::write(home.linked(), "").unwrap();
    let (success, stdout, stderr) = home.run(&["status"]);
    assert!(success, "{stdout}{stderr}");
    assert!(
        stdout.contains(&format!(
            "gateway: main: proxy.example.com:443, route gateway (config)\nlinked-gateways: error: linked \
             gateways {}: not a directory",
            home.linked().display()
        )),
        "{stdout}"
    );
    assert!(stdout.contains("\nagent: "), "{stdout}");
    let (success, _, stderr) = home.run(&["gateway", "list"]);
    assert!(!success);
    assert!(stderr.contains("not a directory"), "{stderr}");
}

#[cfg(not(windows))]
#[test]
fn setup_reports_a_damaged_gateway_file_and_continues() {
    let home = Home::new("setup-damaged");
    home.plant("x.example.toml", "not toml");
    let (success, stdout, stderr) = home.run(&["setup"]);
    assert!(stdout.contains("linked-gateway: error: "), "{stdout}");
    assert!(!success);
    assert!(
        stderr.contains("device keys are only supported on Windows"),
        "{stderr}"
    );
}
