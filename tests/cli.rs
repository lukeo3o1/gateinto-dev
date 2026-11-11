mod isolated;
use std::path::PathBuf;

use isolated::{gateinto as gateinto_command, isolated_root};

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
            default_config(&isolated_root()).display()
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

#[cfg(not(any(windows, target_os = "linux")))]
#[test]
fn setup_requires_windows() {
    let (success, _, stderr) = gateinto_without_terminal(&["setup"]);
    assert!(!success);
    assert!(
        stderr.contains("device keys are only supported on Windows"),
        "{stderr}"
    );
}

#[cfg(target_os = "linux")]
const LINUX_SETUP: &str = "setup is not available on Linux yet: it creates the device key, and \
                           no device key backend for Linux has been decided; run `gateinto uri \
                           register` to register the gateinto:// handler on its own";

#[cfg(target_os = "linux")]
#[test]
fn setup_on_linux_points_to_uri_register() {
    let (success, stdout, stderr) = gateinto_without_terminal(&["setup"]);
    assert!(!success);
    assert!(stdout.starts_with("config: none (no file at "), "{stdout}");
    assert!(!stdout.contains("device-key"), "{stdout}");
    assert!(stderr.ends_with(&format!("{LINUX_SETUP}\n")), "{stderr}");
    assert!(!stderr.contains("only supported on Windows"), "{stderr}");
}

#[cfg(not(windows))]
#[test]
fn commands_never_read_host_xdg_directories() {
    use std::ffi::OsStr;

    let command = gateinto_command();
    let envs: Vec<_> = command.get_envs().collect();
    let root = isolated_root();
    for name in [
        "XDG_CONFIG_HOME",
        "XDG_CONFIG_DIRS",
        "XDG_DATA_HOME",
        "XDG_DATA_DIRS",
    ] {
        assert!(
            envs.contains(&(OsStr::new(name), Some(root.as_os_str()))),
            "{name}"
        );
    }
    assert!(envs.contains(&(OsStr::new("XDG_CURRENT_DESKTOP"), None)));
}

#[cfg(not(any(windows, target_os = "linux")))]
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
            default_config(&isolated_root()).display(),
            default_config(&isolated_root())
                .with_file_name("gateways")
                .display(),
        )
    );
}

#[cfg(target_os = "linux")]
#[test]
fn status_on_linux_reports_the_device_key_terminals_and_os_user_as_they_are() {
    let (success, stdout, stderr) = gateinto_without_terminal(&["status"]);
    assert!(success, "{stdout}{stderr}");
    let (containment, rest): (Vec<&str>, Vec<&str>) = stdout
        .lines()
        .partition(|line| line.starts_with("terminal-containment: "));
    assert_eq!(
        rest.join("\n"),
        format!(
            "key-name: gateinto-device-v1\n\
             device-key: unavailable: no device key backend on Linux; connections are \
             unauthenticated\n\
             config: none (no file at {}; pass --config to use another file)\n\
             linked-gateways: none (no directory at {})\n\
             agent: not running\n\
             uri-handler: not registered\n\
             terminal-sessions: not supported on Linux yet\n\
             os-user: not offered by any session on Linux yet; pidfd_open is available",
            default_config(&isolated_root()).display(),
            default_config(&isolated_root())
                .with_file_name("gateways")
                .display(),
        )
    );
    let [containment] = containment[..] else {
        panic!("{stdout}");
    };
    assert!(
        containment == "terminal-containment: available"
            || containment
                .starts_with("terminal-containment: unavailable: terminal sessions need "),
        "{containment}"
    );
    let order: Vec<&str> = stdout
        .lines()
        .map(|line| line.split_once(':').unwrap().0)
        .skip(5)
        .collect();
    assert_eq!(
        order,
        [
            "uri-handler",
            "terminal-sessions",
            "terminal-containment",
            "os-user"
        ]
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
            "config: {} (default location)\ngateway: main: proxy.example.com:443, route mixed (config)\n",
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
             portal_url = \"https://other.example/\"\nroute = \"gateway\"\n",
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
        "main: proxy.example.com:443, portal https://portal.example.com, route mixed (config)\n\
         newco: proxy.newco.example:8443, portal https://portal.newco.example, route mixed (linked)\n\
         other: 10.0.0.1:443, portal https://other.example, route gateway (linked)\n"
    );
}

#[test]
fn status_marks_linked_gateways() {
    let home = Home::new("status-linked");
    let (success, stdout, stderr) = home.run(&["status"]);
    assert!(success, "{stderr}");
    assert!(
        stdout.contains(&format!(
            "gateway: main: proxy.example.com:443, route mixed (config)\nlinked-gateways: {}\n\
             gateway: newco: proxy.newco.example:8443, route mixed (linked)\n\
             gateway: other: 10.0.0.1:443, route gateway (linked)\n",
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
        "main: proxy.example.com:443, portal https://portal.example.com, route mixed (config)\n\
         other: 10.0.0.1:443, portal https://other.example, route gateway (linked)\n"
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
            "main: proxy.example.com:443, portal https://portal.example.com, route mixed (config)\n\
             newco: proxy.newco.example:8443, portal https://portal.newco.example, route mixed (linked)\n\
             other: 10.0.0.1:443, portal https://other.example, route gateway (linked)\n"
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
            "linked-gateways: {}\ngateway: newco: proxy.newco.example:8443, route mixed (linked)\n\
             gateway: other: 10.0.0.1:443, route gateway (linked)\nlinked-gateway: error: {}: ",
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
            "gateway: main: proxy.example.com:443, route mixed (config)\nlinked-gateways: error: linked \
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
    let expected = if cfg!(target_os = "linux") {
        "setup is not available on Linux yet"
    } else {
        "device keys are only supported on Windows"
    };
    assert!(stderr.contains(expected), "{stderr}");
}

#[cfg(unix)]
mod fake_agent {
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::process::{Command, Output};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    use gateinto::ipc::{self, Endpoint, Response, Server};

    const URL: &str = "https://verify.example.test/device?x=1&cert_sha256=ab";
    const CODE: &str = "WDJB-MJHT";
    const ANSWER_TIMEOUT: Duration = Duration::from_secs(5);

    pub struct FakeAgent {
        dir: PathBuf,
        instance: String,
    }

    impl FakeAgent {
        pub fn new() -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let instance = format!(
                "fake-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            );
            let dir = std::env::temp_dir().join(&instance);
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self { dir, instance }
        }

        #[cfg(feature = "test-hooks")]
        pub fn file(&self, name: &str) -> PathBuf {
            self.dir.join(name)
        }

        pub fn run(
            &self,
            args: &[&str],
            answer: Response,
            mut command: Command,
        ) -> (Output, Option<String>) {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let endpoint = Endpoint::from_env_with(
                |name| match name {
                    "XDG_RUNTIME_DIR" => Some(OsString::from(&self.dir)),
                    "GATEINTO_INSTANCE" => Some(OsString::from(&self.instance)),
                    _ => None,
                },
                "",
            )
            .unwrap();
            let mut server = {
                let _entered = runtime.enter();
                Server::bind(&endpoint).unwrap()
            };
            let answering = runtime.spawn(async move {
                let mut connection = server.accept().await.unwrap();
                let request = ipc::read_request(&mut connection).await.unwrap();
                ipc::write_response(&mut connection, &answer).await.unwrap();
                request.to_string()
            });
            let output = command
                .args(args)
                .env("XDG_RUNTIME_DIR", &self.dir)
                .env("GATEINTO_INSTANCE", &self.instance)
                .stdin(std::process::Stdio::null())
                .output()
                .unwrap();
            let answered =
                runtime.block_on(async { tokio::time::timeout(ANSWER_TIMEOUT, answering).await });
            (output, answered.ok().map(|request| request.unwrap()))
        }
    }

    impl Drop for FakeAgent {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    pub fn pending_verification() -> Response {
        Response::Ok(
            [
                "challenge: 3".to_owned(),
                "gateway: office".to_owned(),
                "origin: https://verify.example.test".to_owned(),
                format!("auth_uri: {URL}"),
                format!("user_code: {CODE}"),
                "expires_in: 300".to_owned(),
                "target: example.com:443".to_owned(),
                "more_targets: 0".to_owned(),
                "suppressed: 0".to_owned(),
            ]
            .to_vec(),
        )
    }

    pub fn assert_no_secret(text: &[u8]) {
        let text = String::from_utf8_lossy(text);
        assert!(!text.contains("verify.example.test"), "{text}");
        assert!(!text.contains(CODE), "{text}");
    }

    #[cfg(feature = "test-hooks")]
    pub fn verification_block() -> String {
        format!(
            "verification required for gateway office\n  target: example.com:443\n  verify at: \
             https://verify.example.test\n  link: {URL}\n  pairing code: {CODE}\n  expires in: \
             300 s\nComplete verification, then retry the connection.\n"
        )
    }
}

#[cfg(unix)]
#[test]
fn a_verification_is_not_shown_on_a_redirected_standard_error() {
    let agent = fake_agent::FakeAgent::new();
    let mut command = gateinto_command();
    command.env_remove("GATEINTO_TEST_VERIFICATION_FILE");
    let (output, request) = agent.run(
        &["session", "verification", "7"],
        fake_agent::pending_verification(),
        command,
    );
    assert_eq!(request.as_deref(), Some("verification 7"));
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    fake_agent::assert_no_secret(&output.stderr);
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        stderr,
        "error: the verification for session 7 was not shown: standard error is not a terminal\n"
    );
}

#[cfg(all(unix, feature = "test-hooks"))]
#[test]
fn a_verification_file_that_cannot_be_written_is_reported_as_such() {
    let agent = fake_agent::FakeAgent::new();
    let mut command = gateinto_command();
    command.env("GATEINTO_TEST_VERIFICATION_FILE", agent.file(""));
    let (output, _) = agent.run(
        &["session", "verification", "7"],
        fake_agent::pending_verification(),
        command,
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    fake_agent::assert_no_secret(&output.stderr);
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.starts_with("error: the verification for session 7 was not shown: "),
        "{stderr}"
    );
    assert!(!stderr.contains("not a terminal"), "{stderr}");
}

#[cfg(all(unix, feature = "test-hooks"))]
#[test]
fn a_shown_verification_carries_the_whole_block_and_nothing_on_standard_output() {
    let agent = fake_agent::FakeAgent::new();
    let shown = agent.file("verification.txt");
    let mut command = gateinto_command();
    command.env("GATEINTO_TEST_VERIFICATION_FILE", &shown);
    let (output, _) = agent.run(
        &["session", "verification", "7"],
        fake_agent::pending_verification(),
        command,
    );
    assert!(output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty());
    fake_agent::assert_no_secret(&output.stderr);
    assert_eq!(
        std::fs::read_to_string(shown).unwrap(),
        fake_agent::verification_block()
    );
}

#[cfg(unix)]
#[test]
fn an_agent_too_old_for_verification_is_named() {
    let agent = fake_agent::FakeAgent::new();
    let (output, _) = agent.run(
        &["session", "verification", "7"],
        gateinto::ipc::Response::Error("invalid request".to_owned()),
        gateinto_command(),
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "error: the agent is too old for verification; restart it\n"
    );
}

#[cfg(unix)]
#[test]
fn the_session_list_notes_a_pending_verification_on_standard_error() {
    let agent = fake_agent::FakeAgent::new();
    let session = r#"{"id":4,"kind":"browser","gateway":"office","upstream":"proxy.example:443","listen":"127.0.0.1:8080","route":"all","auth":"password","started":1700000000,"tunnels":0,"verification":true}"#;
    let (output, request) = agent.run(
        &["session", "list"],
        gateinto::ipc::Response::Ok(vec![session.to_owned()]),
        gateinto_command(),
    );
    assert_eq!(request.as_deref(), Some("list"));
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("ID  KIND"), "{stdout}");
    assert!(!stdout.contains("verification"), "{stdout}");
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "session 4 needs verification; run `gateinto session verification 4` to show it\n"
    );
}
