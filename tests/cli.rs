use std::process::Command;

#[test]
fn prints_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_gateinto"))
        .arg("--version")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("gateinto {}\n", env!("CARGO_PKG_VERSION"))
    );
}

fn gateinto(args: &[&str]) -> (bool, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_gateinto"))
        .args(args)
        .output()
        .unwrap();
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
    let output = Command::new(env!("CARGO_BIN_EXE_gateinto"))
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
